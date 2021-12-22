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
#ifndef __DPVS_PROTO_H__
#define __DPVS_PROTO_H__
#include "list.h"
#include "dpdk.h"
#include "conf/common.h"
#include "ipvs/ipvs.h"
#include "ipvs/conn.h"

struct dp_vs_conn;
#define IPV6_ADDR_LEN_IN_BYTES 16
#define IPV4_ADDR_LEN_IN_BYTES 4

struct dp_vs_proto {
    char                    *name;
    uint8_t                 proto;
    int                     *timeout_table; /* protocol timeout table */

    int (*init)(struct dp_vs_proto *proto);
    int (*exit)(struct dp_vs_proto *proto);

    /* schedule RS and create new conn */
    int (*conn_sched)(struct dp_vs_proto *proto,
                      const struct dp_vs_iphdr *iph,
                      struct rte_mbuf *mbuf,
                      struct dp_vs_conn **conn,
                      int *verdict);

    /* lookup conn by <proto, saddr, sport, daddr, dport>
     * return conn and direction or NULL if miss */
    struct dp_vs_conn *
        (*conn_lookup)(struct dp_vs_proto *proto,
                       const struct dp_vs_iphdr *iph,
                       struct rte_mbuf *mbuf, int *direct,
                       bool reverse, bool *drop, lcoreid_t *peer_cid);

    int (*conn_expire)(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn);

    /* expire quiescent connections timely */
    int (*conn_expire_quiescent)(struct dp_vs_conn *conn);

    /* for NAT mode */
    int (*nat_in_handler)(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn,
                       struct rte_mbuf *mbuf);
    int (*nat_out_handler)(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn,
                       struct rte_mbuf *mbuf);

    /* for FNAT mode */
    int (*fnat_in_handler)(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn,
                       struct rte_mbuf *mbuf);
    int (*fnat_out_handler)(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn,
                       struct rte_mbuf *mbuf);
    /* pre-handler for FNAT */
    int (*fnat_in_pre_handler)(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn,
                       struct rte_mbuf *mbuf);
    int (*fnat_out_pre_handler)(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn,
                       struct rte_mbuf *mbuf);

    /* for SNAT mode */
    int (*snat_in_handler)(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn,
                       struct rte_mbuf *mbuf);
    int (*snat_out_handler)(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn,
                       struct rte_mbuf *mbuf);

    int (*csum_check)(struct dp_vs_proto *proto, int af,
                       struct rte_mbuf *mbuf);
    int (*dump_packet)(struct dp_vs_proto *proto, int af,
                       struct rte_mbuf *mbuf, int off,
                       const char *msg);

    /* try trans connn's states by packet and direction */
    int (*state_trans)(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn,
                       struct rte_mbuf *mbuf,
                       int direct);

    const char *
        (*state_name)(int state);
} __rte_cache_aligned;

int dp_vs_proto_init(void);
int dp_vs_proto_term(void);

struct dp_vs_proto *dp_vs_proto_lookup(uint8_t proto);

#endif /* __DPVS_PROTO_H__ */
