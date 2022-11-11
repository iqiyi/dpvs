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
#include <rte_spinlock.h>

#include "list.h"
#include "ipvs/sched.h"
#include "ipvs/rr.h"
#include "ipvs/wrr.h"
#include "ipvs/wlc.h"
#include "ipvs/conhash.h"
#include "ipvs/fo.h"
#include "ipvs/mh.h"

/*
 *  IPVS scheduler list
 */
static struct list_head dp_vs_schedulers;

/* lock for service table */
static rte_rwlock_t __dp_vs_sched_lock;

/*
 *  Bind a service with a scheduler
 */
int dp_vs_bind_scheduler(struct dp_vs_service *svc,
                         struct dp_vs_scheduler *scheduler)
{
    int ret;

    if (svc == NULL) {
        return EDPVS_INVAL;
    }
    if (scheduler == NULL) {
        return EDPVS_INVAL;
    }

    svc->scheduler = scheduler;

    if (scheduler->init_service) {
        ret = scheduler->init_service(svc);
        if (ret) {
            return ret;
        }
    }

    return EDPVS_OK;
}

/*
 *  Unbind a service with its scheduler
 */
int dp_vs_unbind_scheduler(struct dp_vs_service *svc)
{
    struct dp_vs_scheduler *sched;

    if (svc == NULL) {
        return EDPVS_INVAL;;
    }

    sched = svc->scheduler;
    if (sched == NULL) {
        return EDPVS_INVAL;
    }

    if (sched->exit_service) {
        if (sched->exit_service(svc) != 0) {
            return EDPVS_INVAL;
        }
    }

    svc->scheduler = NULL;
    return EDPVS_OK;
}

/*
 *    Get the gcd of server weights
 */
static int gcd(int a, int b)
{
    int c;

    while ((c = a % b)) {
        a = b;
        b = c;
    }
    return b;
}

int dp_vs_gcd_weight(struct dp_vs_service *svc)
{
    struct dp_vs_dest *dest;
    int weight;
    int g = 0;

    list_for_each_entry(dest, &svc->dests, n_list) {
        weight = rte_atomic16_read(&dest->weight);
        if (weight > 0) {
            if (g > 0)
                g = gcd(weight, g);
            else
                g = weight;
        }
    }
    return g ? g : 1;
}

/*
 * Different workers should start schedule algorith from the dests that are evenly distributed
 * across the whole dest list. It can avoid the clustering of connections across dests on the
 * early phase after the service setup, especially for such scheduling methods as rr/wrr/wlc.
 */
struct list_head * dp_vs_sched_first_dest(const struct dp_vs_service *svc)
{
    int i, cid, loc;
    struct list_head *ini;

    cid = rte_lcore_id();
    ini = svc->dests.next;
    loc = (svc->num_dests / g_slave_lcore_num ?: 1) * g_lcore_id2index[cid] % (svc->num_dests ?: 1);

    for (i = 0; i < loc; i++) {
        ini = ini->next;
        if (unlikely(ini == &svc->dests))
            ini = ini->next;
    }

    return ini;
}

/*
 *  Lookup scheduler and try to load it if it doesn't exist
 */
struct dp_vs_scheduler *dp_vs_scheduler_get(const char *sched_name)
{
    struct dp_vs_scheduler *sched;

    //IP_VS_DBG(2, "%s(): sched_name \"%s\"\n", __func__, sched_name);

    rte_rwlock_read_lock(&__dp_vs_sched_lock);

    list_for_each_entry(sched, &dp_vs_schedulers, n_list) {
        if (strcmp(sched_name, sched->name) == 0) {
            /* HIT */
            rte_rwlock_read_unlock(&__dp_vs_sched_lock);
            return sched;
        }
    }

    rte_rwlock_read_unlock(&__dp_vs_sched_lock);
    return NULL;
}


/*
 *  Register a scheduler in the scheduler list
 */
int register_dp_vs_scheduler(struct dp_vs_scheduler *scheduler)
{
    struct dp_vs_scheduler *sched;

    if (!scheduler) {
        return EDPVS_INVAL;
    }

    if (!scheduler->name) {
        return EDPVS_INVAL;
    }

    rte_rwlock_write_lock(&__dp_vs_sched_lock);

    if (!list_empty(&scheduler->n_list)) {
        rte_rwlock_write_unlock(&__dp_vs_sched_lock);
        return EDPVS_EXIST;
    }

    /*
     *  Make sure that the scheduler with this name doesn't exist
     *  in the scheduler list.
     */
    list_for_each_entry(sched, &dp_vs_schedulers, n_list) {
        if (strcmp(scheduler->name, sched->name) == 0) {
            rte_rwlock_write_unlock(&__dp_vs_sched_lock);
            return EDPVS_EXIST;
        }
    }
    /*
     *      Add it into the d-linked scheduler list
     */
    list_add(&scheduler->n_list, &dp_vs_schedulers);
    rte_rwlock_write_unlock(&__dp_vs_sched_lock);

    return EDPVS_OK;
}

/*
 *  Unregister a scheduler from the scheduler list
 */
int unregister_dp_vs_scheduler(struct dp_vs_scheduler *scheduler)
{
    if (!scheduler) {
        return EDPVS_INVAL;
    }

    rte_rwlock_write_lock(&__dp_vs_sched_lock);
    if (list_empty(&scheduler->n_list)) {
        rte_rwlock_write_unlock(&__dp_vs_sched_lock);
        return EDPVS_NOTEXIST;
    }

    /*
     *      Remove it from the d-linked scheduler list
     */
    list_del(&scheduler->n_list);
    rte_rwlock_write_unlock(&__dp_vs_sched_lock);

    return EDPVS_OK;
}


int dp_vs_sched_init(void)
{
    INIT_LIST_HEAD(&dp_vs_schedulers);
    rte_rwlock_init(&__dp_vs_sched_lock);
    dp_vs_rr_init();
    dp_vs_wrr_init();
    dp_vs_wlc_init();
    dp_vs_conhash_init();
    dp_vs_fo_init();
    dp_vs_mh_init();

    return EDPVS_OK;
}

int dp_vs_sched_term(void)
{
    dp_vs_rr_term();
    dp_vs_wrr_term();
    dp_vs_wlc_term();
    dp_vs_conhash_term();
    dp_vs_fo_term();
    dp_vs_mh_term();

    return EDPVS_OK;
}
