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
#ifndef __DPVS_WHTLST_H__
#define __DPVS_WHTLST_H__
#include "conf/common.h"
#include "ipvs/service.h"
#include "ipset/ipset.h"

struct whtlst_entry {
    struct list_head    list;

    union inet_addr     vaddr;
    uint16_t            vport;
    uint8_t             proto;
    uint8_t             af;

    union inet_addr     subject;
    struct ipset        *set;
    bool                dst_match;  /* internal use of ipset */
};

bool dp_vs_whtlst_filtered(int af, uint8_t proto, const union inet_addr *vaddr,
        uint16_t vport, const union inet_addr *subject, struct rte_mbuf *mbuf);
void dp_vs_whtlst_flush(struct dp_vs_service *svc);

int dp_vs_whtlst_init(void);
int dp_vs_whtlst_term(void);

#endif /* __DPVS_WHTLST_H__ */
