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

#include "ipvs/nat64.h"
#include "ipvs/ipvs.h"
#include "uoa.h"

int mbuf_6to4(struct rte_mbuf *mbuf,
              const struct in_addr *saddr,
              const struct in_addr *daddr)
{
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct rte_ipv4_hdr *ip4h;
    uint8_t next_prot;
    uint8_t ttl;

    /*
     * ext_hdr not support yet
     */
    if (ip6h->ip6_nxt != IPPROTO_TCP &&
        ip6h->ip6_nxt != IPPROTO_UDP &&
        ip6h->ip6_nxt != IPPROTO_SCTP &&
        ip6h->ip6_nxt != IPPROTO_ICMPV6 &&
        ip6h->ip6_nxt != IPPROTO_OPT) {
        return EDPVS_NOTSUPP;
    }
    if (rte_pktmbuf_adj(mbuf, mbuf->l3_len) == NULL)
        return EDPVS_DROP;

    next_prot = ip6h->ip6_nxt;
    ttl = ip6h->ip6_hlim;
    ip4h = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ipv4_hdr));
    if (!ip4h)
        return EDPVS_NOROOM;

    ip4h->version_ihl     = ((4 << 4) | 5);
    ip4h->type_of_service = 0;
    ip4h->total_length    = htons(mbuf->pkt_len);
    ip4h->fragment_offset = htons(RTE_IPV4_HDR_DF_FLAG);
    ip4h->time_to_live    = ttl;
    ip4h->next_proto_id   = next_prot;
    ip4h->hdr_checksum    = 0;
    ip4h->src_addr        = saddr->s_addr;
    ip4h->dst_addr        = daddr->s_addr;
    ip4h->packet_id       = 0; // NO FRAG, so 0 is OK?

    mbuf->l3_len = sizeof(struct rte_ipv4_hdr);

    return EDPVS_OK;
}

int mbuf_4to6(struct rte_mbuf *mbuf,
              const struct in6_addr *saddr,
              const struct in6_addr *daddr)
{
    struct rte_ipv4_hdr *ip4h = ip4_hdr(mbuf);
    struct ip6_hdr *ip6h;
    uint16_t plen;
    uint8_t hops;
    uint8_t next_prot;

    if (mbuf->l3_len != sizeof(struct rte_ipv4_hdr)) {
        return EDPVS_NOTSUPP;
    }
    if (rte_pktmbuf_adj(mbuf, mbuf->l3_len) == NULL)
        return EDPVS_DROP;

    plen = mbuf->pkt_len;
    next_prot = ip4h->next_proto_id;
    hops = ip4h->time_to_live;
    ip6h = (struct ip6_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct ip6_hdr));
    if (!ip6h)
        return EDPVS_NOROOM;

    ip6h->ip6_flow  = 0;
    ip6h->ip6_vfc   = 0x60;
    ip6h->ip6_plen  = htons(plen);
    ip6h->ip6_nxt   = next_prot;
    ip6h->ip6_hlim  = hops;
    ip6h->ip6_src   = *saddr;
    ip6h->ip6_dst   = *daddr;

    mbuf->l3_len = sizeof(struct ip6_hdr);

    return EDPVS_OK;
}

