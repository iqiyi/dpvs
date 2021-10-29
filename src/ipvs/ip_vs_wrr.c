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
#include "ipvs/wrr.h"
/*
 * current destination pointer for weighted round-robin scheduling
 */
struct dp_vs_wrr_mark {
    struct list_head *cl;   /* current list head */
    int cw;         /* current weight */
    int mw;         /* maximum weight */
    int di;         /* decreasing interval */
};

/*
 *    Get the maximum weight of the service destinations.
 */
static int dp_vs_wrr_max_weight(struct dp_vs_service *svc)
{
    struct dp_vs_dest *dest;
    int new_weight, weight = 0;

    list_for_each_entry(dest, &svc->dests, n_list) {
        new_weight = rte_atomic16_read(&dest->weight);
        if (new_weight > weight)
            weight = new_weight;
    }

    return weight;
}

static int dp_vs_wrr_init_svc(struct dp_vs_service *svc)
{
    struct dp_vs_wrr_mark *mark;

    /*
     *    Allocate the mark variable for WRR scheduling
     */
    mark = rte_zmalloc("wrr_mark", sizeof(struct dp_vs_wrr_mark), RTE_CACHE_LINE_SIZE);
    if (mark == NULL) {
        return EDPVS_NOMEM;
    }
    mark->cl = dp_vs_sched_first_dest(svc);
    mark->cw = 0;
    mark->mw = dp_vs_wrr_max_weight(svc);
    mark->di = dp_vs_gcd_weight(svc);
    svc->sched_data = mark;

    return EDPVS_OK;
}

static int dp_vs_wrr_done_svc(struct dp_vs_service *svc)
{
    /*
     *    Release the mark variable
     */
    rte_free(svc->sched_data);

    return EDPVS_OK;
}

static int dp_vs_wrr_update_svc(struct dp_vs_service *svc,
        struct dp_vs_dest *dest __rte_unused, sockoptid_t opt __rte_unused)
{
    struct dp_vs_wrr_mark *mark = svc->sched_data;

    mark->cl = dp_vs_sched_first_dest(svc);
    mark->mw = dp_vs_wrr_max_weight(svc);
    mark->di = dp_vs_gcd_weight(svc);
    if (mark->cw > mark->mw)
        mark->cw = 0;
    return 0;
}

/*
 * Weighted Round-Robin Scheduling
 */
static struct dp_vs_dest *dp_vs_wrr_schedule(struct dp_vs_service *svc,
                    const struct rte_mbuf *mbuf, const struct dp_vs_iphdr *iph __rte_unused)
{
    struct dp_vs_dest *dest;
    struct dp_vs_wrr_mark *mark = svc->sched_data;
    struct list_head *p;

    /*
     * This loop will always terminate, because mark->cw in (0, max_weight]
     * and at least one server has its weight equal to max_weight.
     */
    p = mark->cl;
    while (1) {
        if (mark->cl == &svc->dests) {
            /* it is at the head of the destination list */

            if (mark->cl == mark->cl->next) {
                /* no dest entry */
                dest = NULL;
                goto out;
            }

            mark->cl = svc->dests.next;
            mark->cw -= mark->di;
            if (mark->cw <= 0) {
                mark->cw = mark->mw;
                /*
                 * Still zero, which means no available servers.
                 */
                if (mark->cw == 0) {
                    mark->cl = &svc->dests;
                    dest = NULL;
                    goto out;
                }
            }
        } else
            mark->cl = mark->cl->next;

        if (mark->cl != &svc->dests) {
            /* not at the head of the list */
            dest = list_entry(mark->cl, struct dp_vs_dest, n_list);
            if (dp_vs_dest_is_valid(dest) &&
                rte_atomic16_read(&dest->weight) >= mark->cw) {
                /* got it */
                break;
            }
        }

        if (mark->cl == p && mark->cw == mark->di) {
            /* back to the start, and no dest is found.
               It is only possible when all dests are OVERLOADED */
            dest = NULL;
            goto out;
        }
    }

      out:

    return dest;
}

static struct dp_vs_scheduler dp_vs_wrr_scheduler = {
    .name = "wrr",
    .n_list = LIST_HEAD_INIT(dp_vs_wrr_scheduler.n_list),
    .init_service = dp_vs_wrr_init_svc,
    .exit_service = dp_vs_wrr_done_svc,
    .update_service = dp_vs_wrr_update_svc,
    .schedule = dp_vs_wrr_schedule,
};

int  dp_vs_wrr_init(void)
{
    return register_dp_vs_scheduler(&dp_vs_wrr_scheduler);
}

int  dp_vs_wrr_term(void)
{
    return unregister_dp_vs_scheduler(&dp_vs_wrr_scheduler);
}
