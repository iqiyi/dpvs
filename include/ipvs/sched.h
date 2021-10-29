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
#ifndef __DPVS_SCHED_H__
#define __DPVS_SCHED_H__
#include "list.h"
#include "dpdk.h"
#include "conf/common.h"
#include "ctrl.h"
#include "ipvs/service.h"

struct dp_vs_iphdr;
struct dp_vs_scheduler {
    struct list_head    n_list;
    char                *name;

    struct dp_vs_dest *
        (*schedule)(struct dp_vs_service *svc,
                    const struct rte_mbuf *mbuf, const struct dp_vs_iphdr *iph);

    int (*init_service)(struct dp_vs_service *svc);
    int (*exit_service)(struct dp_vs_service *svc);
    int (*update_service)(struct dp_vs_service *svc, struct dp_vs_dest *dest,
            sockoptid_t opt);
} __rte_cache_aligned;

int dp_vs_sched_init(void);
int dp_vs_sched_term(void);

struct dp_vs_scheduler *
dp_vs_scheduler_get(const char *name);

int dp_vs_bind_scheduler(struct dp_vs_service *svc,
                     struct dp_vs_scheduler *scheduler);

int dp_vs_unbind_scheduler(struct dp_vs_service *svc);

int dp_vs_gcd_weight(struct dp_vs_service *svc);

struct list_head * dp_vs_sched_first_dest(const struct dp_vs_service *svc);

void dp_vs_scheduler_put(struct dp_vs_scheduler *scheduler);

int register_dp_vs_scheduler(struct dp_vs_scheduler *scheduler);

int unregister_dp_vs_scheduler(struct dp_vs_scheduler *scheduler);

#endif /* __DPVS_SCHED_H__ */
