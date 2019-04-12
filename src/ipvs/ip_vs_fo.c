/*
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
 * weighted fail over module
 * see net/netfilter/ipvs/ip_vs_fo.c for reference
 *
 * yangxingwu <xingwu.yang@gmail.com>, Feb 2019, initial.
 *
 */

#include "ipvs/fo.h"

/* weighted fail over scheduling */
static struct dp_vs_dest *dp_vs_fo_schedule(struct dp_vs_service *svc,
        const struct rte_mbuf *mbuf __rte_unused)
{

    struct dp_vs_dest *dest, *hweight = NULL;
    int16_t hw = 0; /* track highest weight */

    /* basic failover functionality
     * find virtual server with highest weight and send it traffic
     */
    list_for_each_entry(dest, &svc->dests, n_list) {
        if (!(dest->flags & DPVS_DEST_F_OVERLOAD) &&
                (dest->flags & DPVS_DEST_F_AVAILABLE) &&
                (rte_atomic16_read(&dest->weight) > hw)) {
            hweight = dest;
            hw = rte_atomic16_read(&dest->weight);
        }
    }

    return hweight;
}

static struct dp_vs_scheduler dp_vs_fo_scheduler = {
    .name     = "fo",
    .n_list   = LIST_HEAD_INIT(dp_vs_fo_scheduler.n_list),
    .schedule = dp_vs_fo_schedule,
};

int dp_vs_fo_init(void)
{
    return register_dp_vs_scheduler(&dp_vs_fo_scheduler);
}

int dp_vs_fo_term(void)
{
    return unregister_dp_vs_scheduler(&dp_vs_fo_scheduler);
}
