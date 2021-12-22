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
#include <netinet/tcp.h>
/*
 *  DPDK IP Virtual Server Syn-Proxy
 *  data structure and functionality definitions
 *
 */

#ifndef __DPVS_SYNPROXY_H__
#define __DPVS_SYNPROXY_H__

#include "dpdk.h"
#include "ipvs/ipvs.h"
#include "ipvs/conn.h"
#include "ipvs/dest.h"
#include "ipvs/service.h"

/* Add MASKs for TCP OPT in "data" coded in cookie */
/* |[21][20][19-16][15-0]|
 * [21]     SACK
 * [20]     TimeStamp
 * [19-16]  snd_wscale
 * [15-0]   MSSIND
 */
#define DP_VS_SYNPROXY_OTHER_BITS   12
#define DP_VS_SYNPROXY_OTHER_MASK   (((uint32_t)1 << DP_VS_SYNPROXY_OTHER_BITS) - 1)

#define DP_VS_SYNPROXY_MSS_BITS     12
#define DP_VS_SYNPROXY_MSS_MASK     ((uint32_t)0xf << DP_VS_SYNPROXY_MSS_BITS)

#define DP_VS_SYNPROXY_SACKOK_BIT   21
#define DP_VS_SYNPROXY_SACKOK_MASK  ((uint32_t)1 << DP_VS_SYNPROXY_SACKOK_BIT)

#define DP_VS_SYNPROXY_TSOK_BIT     20
#define DP_VS_SYNPROXY_TSOK_MASK    ((uint32_t)1 << DP_VS_SYNPROXY_TSOK_BIT)

#define DP_VS_SYNPROXY_SND_WSCALE_BITS  16
#define DP_VS_SYNPROXY_SND_WSCALE_MASK  ((uint32_t)0xf << DP_VS_SYNPROXY_SND_WSCALE_BITS)
#define DP_VS_SYNPROXY_WSCALE_MAX       14

extern struct rte_mempool *dp_vs_synproxy_ack_mbufpool[DPVS_MAX_SOCKET];
#define this_ack_mbufpool (dp_vs_synproxy_ack_mbufpool[rte_socket_id()])

extern int dp_vs_synproxy_ctrl_conn_reuse;

#ifdef CONFIG_SYNPROXY_DEBUG
extern rte_atomic32_t sp_syn_saved;
extern rte_atomic32_t sp_ack_saved;
extern rte_atomic64_t sp_ack_refused;
#endif

#ifdef CONFIG_SYNPROXY_DEBUG
#define sp_dbg_stats32_inc(x) (rte_atomic32_inc(&x))
#define sp_dbg_stats32_dec(x) (rte_atomic32_dec(&x))
#define sp_dbg_stats64_inc(x) (rte_atomic64_inc(&x))
#define sp_dbg_stats64_dec(x) (rte_atomic64_dec(&x))
#else
#define sp_dbg_stats32_inc(x)
#define sp_dbg_stats32_dec(x)
#define sp_dbg_stats64_inc(x)
#define sp_dbg_stats64_dec(x)
#endif

/* add for supporting tcp options in syn-proxy */
struct dp_vs_synproxy_opt {
    uint16_t snd_wscale:8,  /* Window scaling received from sender */
             tstamp_ok:1,   /* TIMESTAMP seen on SYN packet */
             wscale_ok:1,   /* Wscale seen on SYN packet */
             sack_ok:1;     /* SACK seen on SYN packet */
    uint16_t mss_clamp;     /* Max mss, negotiated at connectons setup */
} __rte_cache_aligned;

/* synproxy(syncookies and one-minute-timer) init & cleanup */
int dp_vs_synproxy_init(void);
int dp_vs_synproxy_term(void);

/* Syn-proxy step 1 logic: receive client's Syn. */
int dp_vs_synproxy_syn_rcv(int af, struct rte_mbuf *mbuf,
        const struct dp_vs_iphdr *iph, int *verdict);

/* Syn-proxy step 2 logic: receive client's Ack */
int dp_vs_synproxy_ack_rcv(int af, struct rte_mbuf *mbuf,
        struct tcphdr *th, struct dp_vs_proto *pp,
        struct dp_vs_conn **cpp,
        const struct dp_vs_iphdr *iph, int *verdict);

/* Syn-proxy step 3 logic: receive rs's Syn/Ack. */
int dp_vs_synproxy_synack_rcv(struct rte_mbuf *mbuf, struct dp_vs_conn *cp,
        struct dp_vs_proto *pp, int th_offset, int *verdict);

/* Syn-proxy conn reuse logic: receive client's Ack */
int dp_vs_synproxy_reuse_conn(int af, struct rte_mbuf *mbuf,
        struct dp_vs_conn *cp,
        struct dp_vs_proto *pp,
        const struct dp_vs_iphdr *iph, int *verdict);

/* Store or drop client's ack packet, when dpvs is waiting for rs's Syn/Ack packet */
int dp_vs_synproxy_filter_ack(struct rte_mbuf *mbuf, struct dp_vs_conn *cp,
        struct dp_vs_proto *pp,
        const struct dp_vs_iphdr *iph, int *verdict);

/* Transfer ack seq and sack opt for Out-In packet */
void dp_vs_synproxy_dnat_handler(struct tcphdr *tcph, struct dp_vs_seq *sp_seq);

/* Transer seq for In-Out packet */
int dp_vs_synproxy_snat_handler(struct tcphdr *tcph, struct dp_vs_conn *cp);

/* configuration file support */
void synproxy_keyword_value_init(void);
void install_synproxy_keywords(void);

#endif
