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
#ifndef __DPVS_BLKLST_H__
#define __DPVS_BLKLST_H__
#include "common.h"
#include "ipvs/service.h"
#include "timer.h"

struct blklst_entry {
    struct list_head    list;
    union inet_addr     vaddr;
    union inet_addr     blklst;
    struct dpvs_timer   timer;
    rte_atomic32_t      refcnt;
};

static inline void blklst_put(struct blklst_entry *blklst_node)
{
    rte_atomic32_dec(&blklst_node->refcnt);
}

struct blklst_entry *dp_vs_blklst_lookup(const union inet_addr *vaddr,
                                       const union inet_addr *blklst);
void dp_vs_blklst_flush(struct dp_vs_service *svc);

int dp_vs_blklst_init(void);
int dp_vs_blklst_term(void);

#endif /* __DPVS_BLKLST_H__ */
