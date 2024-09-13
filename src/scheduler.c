/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <assert.h>
#include "conf/common.h"
#include "scheduler.h"

/* Note: lockless, lcore_job can only be register on initialization stage and
 *       unregistered on cleanup stage.
 */
static struct list_head dpvs_lcore_jobs[LCORE_ROLE_MAX][LCORE_JOB_TYPE_MAX];

struct dpvs_role_str {
    dpvs_lcore_role_t role;
    const char *str;
};

const char *dpvs_lcore_role_str(dpvs_lcore_role_t role)
{
    static const char *role_str_tab[] = {
        [LCORE_ROLE_IDLE]          = "lcre_role_idle",
        [LCORE_ROLE_MASTER]        = "lcre_role_master",
        [LCORE_ROLE_FWD_WORKER]    = "lcre_role_fwd_worker",
        [LCORE_ROLE_ISOLRX_WORKER] = "lcre_role_isolrx_worker",
        [LCORE_ROLE_KNI_WORKER]    = "lcore_role_kni_worker",
        [LCORE_ROLE_MAX]           = "lcre_role_null"
    };

    if (likely(role >= LCORE_ROLE_IDLE && role <= LCORE_ROLE_MAX))
        return role_str_tab[role];
    else
        return "lcore_role_unknown";
}

int dpvs_scheduler_init(void)
{
    int ii, jj;
    for (ii = 0; ii < LCORE_ROLE_MAX; ii++) {
        for (jj = 0; jj < LCORE_JOB_TYPE_MAX; jj++) {
            INIT_LIST_HEAD(&dpvs_lcore_jobs[ii][jj]);
        }
    }
    return EDPVS_OK;
}

int dpvs_scheduler_term(void)
{
    return EDPVS_OK;
}

void dpvs_lcore_job_init(struct dpvs_lcore_job *job, char *name,
                         dpvs_lcore_job_t type, job_pt func,
                         uint32_t skip_loops)
{
    if (!job) {
        return;
    }

    job->type = type;
    job->func = func;
    job->skip_loops = skip_loops;
    snprintf(job->name, sizeof(job->name) - 1, "%s", name);
}

int dpvs_lcore_job_register(struct dpvs_lcore_job *lcore_job, dpvs_lcore_role_t role)
{
    struct dpvs_lcore_job *cur;

    if (unlikely(NULL == lcore_job || role >= LCORE_ROLE_MAX))
        return EDPVS_INVAL;

    if (unlikely(LCORE_JOB_SLOW == lcore_job->type && lcore_job->skip_loops <= 0))
        return EDPVS_INVAL;

    list_for_each_entry(cur, &dpvs_lcore_jobs[role][lcore_job->type], list) {
        if (cur == lcore_job) {
            return EDPVS_EXIST;
        }
    }

    list_add_tail(&lcore_job->list, &dpvs_lcore_jobs[role][lcore_job->type]);

    return EDPVS_OK;
}

int dpvs_lcore_job_unregister(struct dpvs_lcore_job *lcore_job, dpvs_lcore_role_t role)
{
    struct dpvs_lcore_job *cur;

    if (unlikely(NULL == lcore_job || role >= LCORE_ROLE_MAX))
        return EDPVS_INVAL;

    list_for_each_entry(cur, &dpvs_lcore_jobs[role][lcore_job->type], list) {
        if (cur == lcore_job) {
            list_del_init(&cur->list);
            return EDPVS_OK;
        }
    }

    return EDPVS_NOTEXIST;
}

#ifdef CONFIG_RECORD_BIG_LOOP

static void print_job_time(char *buf, size_t len, dpvs_lcore_role_t role)
{
    int ii, jj;
    size_t pos = 0;
    struct dpvs_lcore_job *job;
    lcoreid_t cid;

    assert(buf);
    buf[0] = '\0';
    cid = rte_lcore_id();

    if (role < LCORE_ROLE_MAX) {
        for (jj = 0; jj < LCORE_JOB_TYPE_MAX; jj++) {
            list_for_each_entry(job, &dpvs_lcore_jobs[role][jj], list) {
                if (unlikely(pos + 1 >= len))
                    return;
                snprintf(buf + pos, len - pos -1, "%s=%d ",
                        job->name, job->job_time[cid]);
                pos = strlen(buf);
            }
        }
        return;
    }

    for (ii = 0; ii < LCORE_ROLE_MAX; ii++) {
        for (jj = 0; jj < LCORE_JOB_TYPE_MAX; jj++) {
            list_for_each_entry(job, &dpvs_lcore_jobs[ii][jj], list) {
                if (unlikely(pos + 1 >= len))
                    return;
                snprintf(buf + pos, len - pos - 1, "%s=%d ",
                        job->name, job->job_time[cid]);
                pos = strlen(buf);
            }
        }
    }
}
#endif

static inline void do_lcore_job(struct dpvs_lcore_job *job)
{
#ifdef CONFIG_RECORD_BIG_LOOP
    uint64_t job_start, job_end;
    job_start = rte_get_timer_cycles();
#endif

    job->func(job->data);

#ifdef CONFIG_RECORD_BIG_LOOP
    job_end = rte_get_timer_cycles();
    job->job_time[rte_lcore_id()] = (job_end - job_start) * 1000000 / g_cycles_per_sec;
#endif
}

static int dpvs_job_loop(void *arg)
{
    struct dpvs_lcore_job *job;
    lcoreid_t cid = rte_lcore_id();
    dpvs_lcore_role_t role = g_lcore_role[cid];
    this_poll_tick = 0;
#ifdef CONFIG_RECORD_BIG_LOOP
    char buf[512];
    uint32_t loop_time, thres_time;
    uint64_t loop_start, loop_end;
    static uint32_t longest_lcore_loop[DPVS_MAX_LCORE] = { 0 };

    if (likely(role != LCORE_ROLE_MASTER))
        thres_time = BIG_LOOP_THRESH_SLAVE;
    else
        thres_time = BIG_LOOP_THRESH_MASTER;
#endif

    if (cid >= DPVS_MAX_LCORE)
        return EDPVS_OK;

    /* skip irrelative job loops */
    if (role == LCORE_ROLE_MAX)
        return EDPVS_INVAL;
    if (role == LCORE_ROLE_IDLE)
        return EDPVS_IDLE;

    RTE_LOG(INFO, DSCHED, "lcore %02d enter %s loop\n", cid, dpvs_lcore_role_str(role));

    /* do init job */
    list_for_each_entry(job, &dpvs_lcore_jobs[role][LCORE_JOB_INIT], list) {
        do_lcore_job(job);
    }

    while (1) {
#ifdef CONFIG_RECORD_BIG_LOOP
        loop_start = rte_get_timer_cycles();
#endif
        ++this_poll_tick;
        netif_update_worker_loop_cnt();

        /* do normal job */
        list_for_each_entry(job, &dpvs_lcore_jobs[role][LCORE_JOB_LOOP], list) {
            do_lcore_job(job);
        }

        /* do slow job */
        list_for_each_entry(job, &dpvs_lcore_jobs[role][LCORE_JOB_SLOW], list) {
            if (this_poll_tick % job->skip_loops == 0) {
                do_lcore_job(job);
            }
        }

#ifdef CONFIG_RECORD_BIG_LOOP
        loop_end = rte_get_timer_cycles();
        loop_time = (loop_end - loop_start) * 1000000 / g_cycles_per_sec;
        if (loop_time > longest_lcore_loop[cid]) {
            RTE_LOG(WARNING, DSCHED, "update longest_lcore_loop[%d] = %d (<- %d)\n",
                    cid, loop_time, longest_lcore_loop[cid]);
            longest_lcore_loop[cid] = loop_time;
        }
        if (loop_time > thres_time) {
            print_job_time(buf, sizeof(buf), role);
            RTE_LOG(WARNING, DSCHED, "lcore[%d] loop over %d usecs (actual=%d, max=%d):\n%s\n",
                    cid, thres_time, loop_time, longest_lcore_loop[cid], buf);
        }
#endif
    }

    return EDPVS_OK;
}

int dpvs_lcore_start(int is_master)
{
    if (is_master)
        return dpvs_job_loop(NULL);
    return rte_eal_mp_remote_launch(dpvs_job_loop, NULL, SKIP_MAIN);
}
