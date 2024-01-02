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
#ifndef __DP_VS_PROTO_TCP_H__
#define __DP_VS_PROTO_TCP_H__

#include <netinet/in.h>

enum {
    TCP_OPT_EOL         = 0,
    TCP_OPT_NOP         = 1,
    TCP_OPT_MSS         = 2,
    TCP_OPT_WINDOW      = 3,
    TCP_OPT_SACK_PERM   = 4,
    TCP_OPT_SACK        = 5,
    TCP_OPT_TIMESTAMP   = 8,
    TCP_OPT_ADDR        = 254, /* non-standard */
};

#define TCP_OLEN_MSS                4
#define TCP_OLEN_TIMESTAMP          10
#define TCP_OLEN_IP4_ADDR           8
#define TCP_OLEN_IP6_ADDR           20

#define TCP_OLEN_TSTAMP_ALIGNED     12
#define TCP_OLEN_SACK_BASE          2
#define TCP_OLEN_SACK_PERBLOCK      8

#define TCP_OLEN_WSCALE_ALIGNED      4
#define TCP_OLEN_SACKPERMITTED_ALIGNED   4

#define TCP_OPT_TIMESTAMP(tm_spec) \
    (((tm_spec).tv_sec % 100) * 1000000 + \
     ((tm_spec).tv_nsec / 1000))

struct tcpopt_ip4_addr {
    uint8_t opcode;
    uint8_t opsize;
    __be16 port;
    struct in_addr  addr;
} __attribute__((__packed__));

struct tcpopt_ip6_addr {
    uint8_t opcode;
    uint8_t opsize;
    __be16 port;
    struct in6_addr addr;
} __attribute__((__packed__));

struct tcpopt_addr {
    uint8_t opcode;
    uint8_t opsize;
    __be16 port;
    uint8_t addr[16];
} __attribute__((__packed__));

enum {
    DPVS_TCP_S_NONE         = 0,
    DPVS_TCP_S_ESTABLISHED,
    DPVS_TCP_S_SYN_SENT,
    DPVS_TCP_S_SYN_RECV,
    DPVS_TCP_S_FIN_WAIT,
    DPVS_TCP_S_TIME_WAIT,
    DPVS_TCP_S_CLOSE,
    DPVS_TCP_S_CLOSE_WAIT,
    DPVS_TCP_S_LAST_ACK,
    DPVS_TCP_S_LISTEN,
    DPVS_TCP_S_SYNACK,
    DPVS_TCP_S_LAST
};

struct tcp_state {
    int next_state[DPVS_TCP_S_LAST];
};

#define sNO DPVS_TCP_S_NONE
#define sES DPVS_TCP_S_ESTABLISHED
#define sSS DPVS_TCP_S_SYN_SENT
#define sSR DPVS_TCP_S_SYN_RECV
#define sFW DPVS_TCP_S_FIN_WAIT
#define sTW DPVS_TCP_S_TIME_WAIT
#define sCL DPVS_TCP_S_CLOSE
#define sCW DPVS_TCP_S_CLOSE_WAIT
#define sLA DPVS_TCP_S_LAST_ACK
#define sLI DPVS_TCP_S_LISTEN
#define sSA DPVS_TCP_S_SYNACK

struct tcphdr *tcp_hdr(const struct rte_mbuf *mbuf);
void tcp4_send_csum(struct rte_ipv4_hdr *iph, struct tcphdr *th);
void tcp6_send_csum(struct rte_ipv6_hdr *iph, struct tcphdr *th);
int tcp_send_csum(int af, int iphdrlen, struct tcphdr *th,
        const struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
        struct netif_port *dev);
struct rte_mempool *get_mbuf_pool(const struct dp_vs_conn *conn, int dir);
void install_proto_tcp_keywords(void);
void tcp_keyword_value_init(void);
void tcp_in_adjust_seq(struct dp_vs_conn *conn, struct tcphdr *th);

#endif
