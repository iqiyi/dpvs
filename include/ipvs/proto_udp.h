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
#ifndef __DP_VS_PROTO_UDP_H__
#define __DP_VS_PROTO_UDP_H__

#include <netinet/udp.h>
#include "uoa.h"

enum {
    DPVS_UDP_S_NONE     = 0,
    DPVS_UDP_S_ONEWAY,
    DPVS_UDP_S_NORMAL,
    DPVS_UDP_S_LAST
};

extern int g_defence_udp_drop;

void install_proto_udp_keywords(void);
void udp_keyword_value_init(void);

void udp4_send_csum(struct rte_ipv4_hdr *iph, struct rte_udp_hdr *uh);
void udp6_send_csum(struct rte_ipv6_hdr *iph, struct rte_udp_hdr *uh);
int udp_send_csum(int af, int iphdrlen, struct rte_udp_hdr *uh,
        const struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
        const struct opphdr *opp, struct netif_port *dev);

#endif
