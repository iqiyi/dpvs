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

#ifndef __SCHEDULER_H__
#define __SCHEDULER_H__

#include "netif.h"
#include "global_data.h"

#define RTE_LOGTYPE_DSCHED RTE_LOGTYPE_USER1

#ifdef CONFIG_RECORD_BIG_LOOP
#define BIG_LOOP_THRESH_SLAVE   100         /* microsecond time for slave lcore big loop threshold */
#define BIG_LOOP_THRESH_MASTER  2000        /* microsecond time for master lcore big loop threshold */
#endif

typedef enum dpvs_lcore_job_type {
    LCORE_JOB_INIT,
    LCORE_JOB_LOOP,
    LCORE_JOB_SLOW,
    LCORE_JOB_TYPE_MAX
} dpvs_lcore_job_t;

typedef void (*job_pt)(void *arg);

struct dpvs_lcore_job
{
    char name[32];
    void (*func)(void *arg);
    void *data;
    dpvs_lcore_job_t type;
    uint32_t skip_loops;        /* for LCORE_JOB_SLOW type only */
#ifdef CONFIG_RECORD_BIG_LOOP
    uint32_t job_time[DPVS_MAX_LCORE];
#endif
    struct list_head list;
} __rte_cache_aligned;

struct dpvs_lcore_job_array {
    struct dpvs_lcore_job job;
    dpvs_lcore_role_t role;
};

const char *dpvs_lcore_role_str(dpvs_lcore_role_t role);

void dpvs_lcore_job_init(struct dpvs_lcore_job *job, char *name,
                         dpvs_lcore_job_t type, job_pt func,
                         uint32_t skip_loops);
int dpvs_lcore_job_register(struct dpvs_lcore_job *lcore_job, dpvs_lcore_role_t role);
int dpvs_lcore_job_unregister(struct dpvs_lcore_job *lcore_job, dpvs_lcore_role_t role);
int dpvs_lcore_start(int is_master);

int dpvs_scheduler_init(void);
int dpvs_scheduler_term(void);

#endif
