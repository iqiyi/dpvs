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
 * dpvs XOA implementation.
 * NOTE: Do not recalculate checksum of ipv4 header!!!
 *
 * chennan.7733@bytedance.com, May 2020, initial.
 */
#ifndef __DPVS_XOA_H__
#define __DPVS_XOA_H__

#include "dpdk.h"
#include "conf/inet.h"
#include "ipvs/conn.h"

/*
 * XOA Header:
 * 1. A kind of extend header for IPv4 or IPv6 packets.
 * 2. Store 4-tuples: (CIP/CPORT, VIP/VPORT).
 *
 * IPv4
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      type     |     length    |    operation  |    padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         CPort                 |             VPort             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Client Address                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Virtual Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * IPv6
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  NextHeader  | HeaderLength  |   OptionType  | OptionLength  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         CPort                 |             VPort             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                        Client Address                         +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                        Virtual Address                        +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define DPVS_XOA_HDRTYPE_ASYM       30
#define DPVS_XOA_HDRTYPE_SYM        31
#define DPVS_XOA_HDRLEN_V4          16
#define DPVS_XOA_HDRLEN_V6          40

union dp_vs_addr_pair {
    struct {
        struct in_addr      saddr;
        struct in_addr      daddr;
    } ipv4;

    struct {
        struct in6_addr     saddr;
        struct in6_addr     daddr;
    } ipv6;
};

struct dp_vs_xoa_hdr {
    union {
        struct {
            uint8_t         type;
            uint8_t         length;
            uint8_t         operation;
            uint8_t         padding;
        } ipv4;

        struct {
            uint8_t         nexthdr;
            uint8_t         hdrlen;
            uint8_t         option;
            uint8_t         optlen;
        } ipv6;
    } header;
#define ipv4_type       header.ipv4.type
#define ipv4_length     header.ipv4.length
#define ipv4_operation  header.ipv4.operation
#define ipv4_padding    header.ipv4.padding

#define ipv6_nexthdr    header.ipv6.nexthdr
#define ipv6_hdrlen     header.ipv6.hdrlen
#define ipv6_option     header.ipv6.option
#define ipv6_optlen     header.ipv6.optlen

    uint16_t                sport;
    uint16_t                dport;
    union dp_vs_addr_pair   addrs;
#define ipv4_saddr      addrs.ipv4.saddr
#define ipv4_daddr      addrs.ipv4.daddr
#define ipv6_saddr      addrs.ipv6.saddr
#define ipv6_daddr      addrs.ipv6.daddr
};

static inline int dp_vs_xoa_length(int af)
{
    return (af == AF_INET6) ? DPVS_XOA_HDRLEN_V6 : DPVS_XOA_HDRLEN_V4;
}

int dp_vs_xoa_get_iplen(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
                        int *iphdr_len, int *iptot_len, int *xoa_len,
                        uint32_t mtu);
void *dp_vs_xoa_insert(struct rte_mbuf *mbuf, void *iph,
                       int iptot_len, int iphdr_len, int xoa_len);
void dp_vs_xoa4_fill(struct dp_vs_xoa_hdr *xoah, int af,
                     union inet_addr *saddr, union inet_addr *daddr,
                     uint16_t sport, uint16_t dport, bool is_asym_trans);
void dp_vs_xoa6_fill(struct dp_vs_xoa_hdr *xoah, int af,
                     union inet_addr *saddr, union inet_addr *daddr,
                     uint16_t sport, uint16_t dport,
                     uint8_t next_proto, bool is_asym_trans);

#endif  /* __DPVS_XOA_H__*/
