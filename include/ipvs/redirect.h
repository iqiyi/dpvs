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
#ifndef __DPVS_REDIRECT_H__
#define __DPVS_REDIRECT_H__
#include "conf/common.h"
#include "list.h"
#include "dpdk.h"
#include "netif.h"
#include "ipvs/conn.h"
#include "ipvs/dest.h"

/*
 * The conneciton redirect tuple is only for the reverse tuple
 * (inside -> outside) in nat-mode.
 */
struct dp_vs_redirect {
    struct list_head     list;

    uint8_t              af;
    uint8_t              proto;
    lcoreid_t            cid;
    uint8_t              padding;

    union inet_addr      saddr;
    union inet_addr      daddr;
    uint16_t             sport;
    uint16_t             dport;

    struct rte_mempool  *redirect_pool;
} __rte_cache_aligned;

struct dp_vs_redirect *dp_vs_redirect_alloc(enum dpvs_fwd_mode fwdmode);
void dp_vs_redirect_free(struct dp_vs_conn *conn);
void dp_vs_redirect_hash(struct dp_vs_conn *conn);
void dp_vs_redirect_unhash(struct dp_vs_conn *conn);
struct dp_vs_redirect *dp_vs_redirect_get(int af, uint16_t proto,
    const union inet_addr *saddr, const union inet_addr *daddr,
    uint16_t sport, uint16_t dport);
void dp_vs_redirect_init(struct dp_vs_conn *conn);
int dp_vs_redirect_table_init(void);
int dp_vs_redirect_pkt(struct rte_mbuf *mbuf, lcoreid_t peer_cid);
void dp_vs_redirect_ring_proc(lcoreid_t cid);
int dp_vs_redirects_init(void);
int dp_vs_redirects_term(void);

#endif /* __DPVS_REDIRECT_H__ */
