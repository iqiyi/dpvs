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
#include "ipvs/wlc.h"

static inline unsigned int dp_vs_wlc_dest_overhead(struct dp_vs_dest *dest)
{
    return (rte_atomic32_read(&dest->actconns) << 8) +
           rte_atomic32_read(&dest->inactconns);
}

static struct dp_vs_dest *dp_vs_wlc_schedule(struct dp_vs_service *svc,
                    const struct rte_mbuf *mbuf, const struct dp_vs_iphdr *iph __rte_unused)
{
    struct dp_vs_dest *dest, *least;
    unsigned int loh, doh;

    /*
     * We calculate the load of each dest server as follows:
     *                (dest overhead) / dest->weight
     *
     * The server with weight=0 is quiesced and will not receive any
     * new connections.
     */

    list_for_each_entry(dest, &svc->dests, n_list) {
        if (dp_vs_dest_is_valid(dest)) {
            least = dest;
            loh = dp_vs_wlc_dest_overhead(least);
            goto nextstage;
        }
    }
    return NULL;

    /*
     *    Find the destination with the least load.
     */
nextstage:
    list_for_each_entry_continue(dest, &svc->dests, n_list) {
        if (dest->flags & DPVS_DEST_F_OVERLOAD)
            continue;
        doh = dp_vs_wlc_dest_overhead(dest);
        if (loh * rte_atomic16_read(&dest->weight) >
            doh * rte_atomic16_read(&least->weight)) {
            least = dest;
            loh = doh;
        }
    }

    return least;
}

static struct dp_vs_scheduler dp_vs_wlc_scheduler = {
    .name = "wlc",
    .n_list = LIST_HEAD_INIT(dp_vs_wlc_scheduler.n_list),
    .schedule = dp_vs_wlc_schedule,
};

int dp_vs_wlc_init(void)
{
    return register_dp_vs_scheduler(&dp_vs_wlc_scheduler);
}

int dp_vs_wlc_term(void)
{
    return unregister_dp_vs_scheduler(&dp_vs_wlc_scheduler);
}
