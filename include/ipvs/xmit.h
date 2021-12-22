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
#ifndef __DPVS_XMIT_H__
#define __DPVS_XMIT_H__
#include "dpdk.h"
#include "ipvs/proto.h"
#include "ipvs/conn.h"

int dp_vs_xmit_fnat(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf);

int dp_vs_out_xmit_fnat(struct dp_vs_proto *prot,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf);

void dp_vs_xmit_icmp(struct rte_mbuf *mbuf,
                     struct dp_vs_proto *prot,
                     struct dp_vs_conn *conn,
                     int dir);

int dp_vs_xmit_dr(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf);

int dp_vs_xmit_snat(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf);

int dp_vs_out_xmit_snat(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf);

int dp_vs_xmit_nat(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf);

int dp_vs_out_xmit_nat(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf);

int dp_vs_xmit_tunnel(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf);

void install_xmit_keywords(void);

#endif /* __DPVS_XMIT_H__ */
