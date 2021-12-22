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
#ifndef __DPVS_NAT64_H__
#define __DPVS_NAT64_H__

#include "ipv4.h"
#include "ipv6.h"

static inline int mbuf_nat6to4_len(struct rte_mbuf *mbuf)
{
    int offset = sizeof(struct ip6_hdr);
    uint8_t nexthdr = ip6_hdr(mbuf)->ip6_nxt;
    int len;

    offset = ip6_skip_exthdr(mbuf, offset, &nexthdr);
    len = mbuf->pkt_len - offset + sizeof(struct rte_ipv4_hdr);

    return len;
}

static inline int mbuf_nat4to6_len(struct rte_mbuf *mbuf)
{
    return (mbuf->pkt_len - ip4_hdrlen(mbuf) + sizeof(struct ip6_hdr));
}

int mbuf_6to4(struct rte_mbuf *mbuf,
              const struct in_addr *saddr,
              const struct in_addr *daddr);

int mbuf_4to6(struct rte_mbuf *mbuf,
              const struct in6_addr *saddr,
              const struct in6_addr *daddr);

#endif /* __DPVS_NAT64_H__ */
