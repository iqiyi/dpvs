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
#include "ipvs/rnd.h"

/*
 * Random Scheduling
 * 
 * This scheduler randomly selects a destination server from the available
 * servers. It's particularly useful in K8S clusters where you want to
 * distribute load evenly without maintaining state.
 */
static int dp_vs_rnd_init_svc(struct dp_vs_service *svc)
{
    /* Random scheduler doesn't need to maintain state */
    svc->sched_data = NULL;

    return EDPVS_OK;
}

static int dp_vs_rnd_update_svc(struct dp_vs_service *svc,
        struct dp_vs_dest *dest __rte_unused, sockoptid_t opt __rte_unused)
{
    /* No state to update */
    return EDPVS_OK;
}

/*
 * Random Scheduling Algorithm
 * 
 * This function randomly selects a valid destination from the service.
 * It uses a two-pass approach:
 * 1. First pass: count the number of valid destinations
 * 2. Second pass: randomly select one of them
 * 
 * This approach avoids dynamic memory allocation and provides good
 * performance while ensuring fair distribution.
 */
static struct dp_vs_dest *dp_vs_rnd_schedule(struct dp_vs_service *svc,
                    const struct rte_mbuf *mbuf __rte_unused, 
                    const struct dp_vs_iphdr *iph __rte_unused)
{
    struct dp_vs_dest *dest;
    int count = 0;
    int selected = 0;
    int i = 0;
    struct dp_vs_dest *result = NULL;

    /* First pass: count valid destinations */
    list_for_each_entry(dest, &svc->dests, n_list) {
        if (dp_vs_dest_is_valid(dest)) {
            count++;
        }
    }

    /* If no valid destination, return NULL */
    if (count == 0) {
        return NULL;
    }

    /* Randomly select one destination from the valid ones */
    selected = rte_rand_max(count);

    /* Second pass: find the selected destination */
    list_for_each_entry(dest, &svc->dests, n_list) {
        if (dp_vs_dest_is_valid(dest)) {
            if (i == selected) {
                result = dest;
                break;
            }
            i++;
        }
    }

    return result;
}

static struct dp_vs_scheduler dp_vs_rnd_scheduler = {
    .name = "rnd",       /* name */
    .n_list = LIST_HEAD_INIT(dp_vs_rnd_scheduler.n_list),
    .init_service = dp_vs_rnd_init_svc,
    .update_service = dp_vs_rnd_update_svc,
    .schedule = dp_vs_rnd_schedule,
};

int dp_vs_rnd_init(void)
{
    return register_dp_vs_scheduler(&dp_vs_rnd_scheduler);
}

int dp_vs_rnd_term(void)
{
    return unregister_dp_vs_scheduler(&dp_vs_rnd_scheduler);
}

