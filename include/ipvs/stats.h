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
#ifndef __DPVS_STATS_H__
#define __DPVS_STATS_H__

#include <stdint.h>
#include "dpdk.h"
#include "conf/stats.h"
#include "ipvs/service.h"

struct dp_vs_conn;

/* statistics for FULLNAT and SYNPROXY */
enum  dp_vs_estats_type {
    FULLNAT_ADD_TOA_OK = 1,
    FULLNAT_ADD_TOA_FAIL_LEN,
    FULLNAT_ADD_TOA_HEAD_FULL,
    FULLNAT_ADD_TOA_FAIL_MEM,
    FULLNAT_ADD_TOA_FAIL_PROTO,
    FULLNAT_CONN_REUSED,
    FULLNAT_CONN_REUSED_CLOSE,
    FULLNAT_CONN_REUSED_TIMEWAIT,
    FULLNAT_CONN_REUSED_FINWAIT,
    FULLNAT_CONN_REUSED_CLOSEWAIT,
    FULLNAT_CONN_REUSED_LASTACK,
    FULLNAT_CONN_REUSED_ESTAB,
    SYNPROXY_RS_ERROR,
    SYNPROXY_NULL_ACK,
    SYNPROXY_BAD_ACK,
    SYNPROXY_OK_ACK,
    SYNPROXY_SYN_CNT,
    SYNPROXY_ACK_STORM,
    SYNPROXY_SYNSEND_QLEN,
    SYNPROXY_CONN_REUSED,
    SYNPROXY_CONN_REUSED_CLOSE,
    SYNPROXY_CONN_REUSED_TIMEWAIT,
    SYNPROXY_CONN_REUSED_FINWAIT,
    SYNPROXY_CONN_REUSED_CLOSEWAIT,
    SYNPROXY_CONN_REUSED_LASTACK,
    DEFENCE_IP_FRAG_DROP,
    DEFENCE_SCTP_DROP,
    DEFENCE_TCP_DROP,
    DEFENCE_UDP_DROP,
    FAST_XMIT_REJECT,
    FAST_XMIT_PASS,
    FAST_XMIT_SKB_COPY,
    FAST_XMIT_NO_MAC,
    FAST_XMIT_SYNPROXY_SAVE,
    FAST_XMIT_DEV_LOST,
    FAST_XMIT_REJECT_INSIDE,
    FAST_XMIT_PASS_INSIDE,
    FAST_XMIT_SYNPROXY_SAVE_INSIDE,
    RST_IN_SYN_SENT,
    RST_OUT_SYN_SENT,
    RST_IN_ESTABLISHED,
    RST_OUT_ESTABLISHED,
    GRO_PASS,
    LRO_REJECT,
    XMIT_UNEXPECTED_MTU,
    CONN_SCHED_UNREACH,
    SYNPROXY_NO_DEST,
    CONN_EXCEEDED,
    DP_VS_EXT_STAT_LAST
};

struct dp_vs_estats {
    unsigned long mibs[DP_VS_EXT_STAT_LAST];
} __rte_cache_aligned;

int dp_vs_stats_init(void);
int dp_vs_stats_term(void);

void dp_vs_stats_clear(struct dp_vs_stats *stats);
int dp_vs_stats_add(struct dp_vs_stats *dst, struct dp_vs_stats *src);
int dp_vs_stats_in(struct dp_vs_conn *conn, struct rte_mbuf *mbuf);
int dp_vs_stats_out(struct dp_vs_conn *conn, struct rte_mbuf *mbuf);
void dp_vs_stats_conn(struct dp_vs_conn *conn);

void dp_vs_estats_inc(enum dp_vs_estats_type field);
void dp_vs_estats_clear(void);
uint64_t dp_vs_estats_get(enum dp_vs_estats_type field);

#endif /* __DPVS_STATS_H__ */
