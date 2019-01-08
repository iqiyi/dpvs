/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
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
#include "ipvs/rr.h"


static int dp_vs_rr_init_svc(struct dp_vs_service *svc)
{
    svc->sched_data = &svc->dests;
    return EDPVS_OK;
}

static int dp_vs_rr_update_svc(struct dp_vs_service *svc,
        struct dp_vs_dest *dest __rte_unused, sockoptid_t opt __rte_unused)
{
    svc->sched_data = &svc->dests;
    return EDPVS_OK;
}

/*
 * Round-Robin Scheduling
 */
static struct dp_vs_dest *dp_vs_rr_schedule(struct dp_vs_service *svc,
                                            const struct rte_mbuf *mbuf)
{
    struct list_head *p, *q;
    struct dp_vs_dest *dest;

    rte_rwlock_write_lock(&svc->sched_lock);

    p = (struct list_head *)svc->sched_data;
    p = p->next;
    q = p;

    do {
        /* skip list head */
        if (q == &svc->dests) {
            q = q->next;
            continue;
        }

        dest = list_entry(q, struct dp_vs_dest, n_list);
        if (dp_vs_dest_is_valid(dest))
            /* HIT */
            goto out;
        q = q->next;
    } while (q != p);
    rte_rwlock_write_unlock(&svc->sched_lock);

    return NULL;

out:
    svc->sched_data = q;
    rte_rwlock_write_unlock(&svc->sched_lock);

    return dest;
}

static struct dp_vs_scheduler dp_vs_rr_scheduler = {
    .name = "rr",       /* name */
//    .refcnt = ATOMIC_INIT(0),
    .n_list = LIST_HEAD_INIT(dp_vs_rr_scheduler.n_list),
    .init_service = dp_vs_rr_init_svc,
    .update_service = dp_vs_rr_update_svc,
    .schedule = dp_vs_rr_schedule,
};

int dp_vs_rr_init(void)
{
    return register_dp_vs_scheduler(&dp_vs_rr_scheduler);
}

int dp_vs_rr_term(void)
{
    return unregister_dp_vs_scheduler(&dp_vs_rr_scheduler);
}
