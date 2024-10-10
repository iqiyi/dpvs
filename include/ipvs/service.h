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
#ifndef __DPVS_SVC_H__
#define __DPVS_SVC_H__

#include <stdint.h>
#include <net/if.h>
#include "ipvs/stats.h"
#include "ipvs/dest.h"
#include "inet.h"
#include "list.h"
#include "dpdk.h"
#include "netif.h"
#include "ipvs/ipvs.h"
#include "ipvs/sched.h"
#include "conf/match.h"
#include "conf/service.h"

#define RTE_LOGTYPE_SERVICE             RTE_LOGTYPE_USER1

/* DP_VS_SVC_F_XXX should always be the same with IP_VS_SVC_F_XXX */
#define DP_VS_SVC_F_PERSISTENT          IP_VS_SVC_F_PERSISTENT
#define DP_VS_SVC_F_HASHED              IP_VS_SVC_F_HASHED
#define DP_VS_SVC_F_ONEPACKET           IP_VS_SVC_F_ONEPACKET
#define DP_VS_SVC_F_SYNPROXY            IP_VS_SVC_F_SYNPROXY
#define DP_VS_SVC_F_EXPIRE_QUIESCENT    IP_VS_SVC_F_EXPIRE_QUIESCENT
#define DP_VS_SVC_F_SCHED1              IP_VS_SVC_F_SCHED1
#define DP_VS_SVC_F_SCHED2              IP_VS_SVC_F_SCHED2
#define DP_VS_SVC_F_SCHED3              IP_VS_SVC_F_SCHED3
#define DP_VS_SVC_F_SIP_HASH            IP_VS_SVC_F_SIP_HASH
#define DP_VS_SVC_F_QID_HASH            IP_VS_SVC_F_QID_HASH
#define DP_VS_SVC_F_MATCH               IP_VS_SVC_F_MATCH
#define DP_VS_SVC_F_QUIC                IP_VS_SVC_F_QUIC

/* virtual service */
struct dp_vs_service {
    struct list_head    s_list;     /* node for normal service table */
    struct list_head    f_list;     /* node for fwmark service table */
    struct list_head    m_list;     /* node for match  service table */
    rte_atomic32_t      refcnt;     /* svc is per core, conn will not refer to svc, but dest will.
                                     *  while conn will refer to dest */

    /*
     * to identify a service
     * 1. <af, proto, vip, vport>
     * 2. fwmark (no use now).
     * 3. match.
     */
    int                 af;
    uint8_t             proto;      /* TCP/UDP/... */
    uint8_t             proxy_protocol;
    uint16_t            port;
    uint32_t            fwmark;
    union inet_addr     addr;       /* virtual IP address */
    struct dp_vs_match  *match;

    unsigned            flags;
    unsigned            timeout;
    unsigned            conn_timeout;
    unsigned            bps;
    unsigned            limit_proportion;
    uint32_t            netmask;

    struct list_head    dests;      /* real services (dp_vs_dest{}) */
    uint32_t            num_dests;
    long                weight;     /* sum of servers weight */
    struct dest_check_configs check_conf;

    struct dp_vs_scheduler  *scheduler;
    void                *sched_data;

    struct dp_vs_stats  stats;

    /* FNAT only */
    struct list_head    laddr_list; /* local address (LIP) pool */
    struct list_head    *laddr_curr;
    uint32_t            num_laddrs;

    /* ... flags, timer ... */
} __rte_cache_aligned;


int dp_vs_service_init(void);
int dp_vs_service_term(void);

struct dp_vs_service *
dp_vs_service_lookup(int af, uint16_t protocol,
                     const union inet_addr *vaddr,
                     uint16_t vport, uint32_t fwmark,
                     const struct rte_mbuf *mbuf,
                     const struct dp_vs_match *match,
                     lcoreid_t cid);

void dp_vs_service_bind(struct dp_vs_dest *dest, struct dp_vs_service *svc);

void dp_vs_service_unbind(struct dp_vs_dest *dest);

void dp_vs_service_put(struct dp_vs_service *svc);

struct dp_vs_service *dp_vs_vip_lookup(int af, uint16_t protocol,
                                       const union inet_addr *vaddr,
                                       lcoreid_t cid);
void dp_vs_copy_udest_compat(struct dp_vs_dest_conf *udest, dpvs_dest_compat_t *udest_compat);

#endif /* __DPVS_SVC_H__ */
