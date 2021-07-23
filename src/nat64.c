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
#include "dpdk.h"
#include "nat64.h"
#include "ipvs/xoa.h"
#include "ipvs/ipvs.h"

int mbuf_6to4(struct rte_mbuf *mbuf,
              const struct in_addr *saddr,
              const struct in_addr *daddr)
{
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct dp_vs_xoa_hdr *xoah = (struct dp_vs_xoa_hdr *)(ip6h + 1);
    struct rte_ipv4_hdr *ip4h;
    uint8_t ihl, ttl, next_prot, optlen = 0;
    uint16_t plen;

    ttl  = ip6h->ip6_hlim;
    plen = ntohs(ip6h->ip6_plen);
    next_prot = ip6h->ip6_nxt;
    ihl = sizeof(struct rte_ipv4_hdr) >> 2;

    if (next_prot != IPPROTO_TCP
        && next_prot != IPPROTO_UDP
        && next_prot != IPPROTO_ICMPV6
        && next_prot != IPPROTO_DSTOPTS)
    {
        return EDPVS_NOTSUPP;
    }

    if (next_prot == IPPROTO_DSTOPTS) {
        next_prot = xoah->ipv6_nexthdr;

        xoah->ipv4_type      = DPVS_XOA_HDRTYPE_SYM;
        xoah->ipv4_length    = (xoah->ipv6_hdrlen + 1) << 3;
        xoah->ipv4_operation = 1;
        xoah->ipv4_padding   = 0;

        ihl += DPVS_XOA_HDRLEN_V6 >> 2;
        optlen = xoah->ipv4_length;
    }

    /* remove IPv6 header */
    if (rte_pktmbuf_adj(mbuf, sizeof(struct ip6_hdr)) == NULL) {
        return EDPVS_DROP;
    }

    /* add IPv4 header */
    ip4h = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf,
                                        sizeof(struct rte_ipv4_hdr));
    if (!ip4h) {
        return EDPVS_NOROOM;
    }

    ip4h->version_ihl     = ((4 << 4) | ihl);
    ip4h->type_of_service = 0;
    ip4h->total_length    = htons(sizeof(struct rte_ipv4_hdr) + plen);
    ip4h->fragment_offset = htons(RTE_IPV4_HDR_DF_FLAG);
    ip4h->time_to_live    = ttl;
    ip4h->next_proto_id   = next_prot;
    ip4h->hdr_checksum    = 0;
    ip4h->src_addr        = saddr->s_addr;
    ip4h->dst_addr        = daddr->s_addr;
    ip4h->packet_id       = 0; // NO FRAG, so 0 is OK?

    mbuf->l3_len = sizeof(struct rte_ipv4_hdr) + optlen;
#ifdef CONFIG_DPVS_IPVS_DEBUG
    dp_vs_mbuf_show(__func__, mbuf);
#endif

    return EDPVS_OK;
}

int mbuf_4to6(struct rte_mbuf *mbuf,
              const struct in6_addr *saddr,
              const struct in6_addr *daddr)
{
    struct rte_ipv4_hdr *ip4h = ip4_hdr(mbuf);
    struct dp_vs_xoa_hdr *xoah = (struct dp_vs_xoa_hdr *)(ip4h + 1);
    struct ip6_hdr *ip6h;
    uint16_t plen, ext_hdr_len = 0;
    uint8_t hops, next_prot;

    hops      = ip4h->time_to_live;
    next_prot = ip4h->next_proto_id;

    if (next_prot != IPPROTO_TCP
        && next_prot != IPPROTO_UDP
        && next_prot != IPPROTO_ICMP)
    {
        return EDPVS_NOTSUPP;
    }

    if (xoah->ipv4_type == DPVS_XOA_HDRTYPE_SYM
        && mbuf->l3_len == (sizeof(struct rte_ipv4_hdr) + DPVS_XOA_HDRLEN_V4))
    {
        ext_hdr_len = xoah->ipv4_length;

        xoah->ipv6_nexthdr = next_prot;
        xoah->ipv6_hdrlen  = (xoah->ipv4_length >> 3) - 1;
        xoah->ipv6_option  = DPVS_XOA_HDRTYPE_SYM;
        xoah->ipv6_optlen  = DPVS_XOA_HDRLEN_V4 - 4;

        next_prot = IPPROTO_DSTOPTS;
    }

    /* remove IPv4 header */
    if (rte_pktmbuf_adj(mbuf, sizeof(struct rte_ipv4_hdr)) == NULL) {
        return EDPVS_DROP;
    }

    plen = mbuf->pkt_len;

    /* add IPv6 header */
    ip6h = (struct ip6_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct ip6_hdr));
    if (!ip6h) {
        return EDPVS_NOROOM;
    }

    ip6h->ip6_flow  = 0;
    ip6h->ip6_vfc   = 0x60;
    ip6h->ip6_plen  = htons(plen);
    ip6h->ip6_nxt   = next_prot;
    ip6h->ip6_hlim  = hops;
    ip6h->ip6_src   = *saddr;
    ip6h->ip6_dst   = *daddr;

    mbuf->l3_len = sizeof(struct ip6_hdr) + ext_hdr_len;
#ifdef CONFIG_DPVS_IPVS_DEBUG
    dp_vs_mbuf_show(__func__, mbuf);
#endif

    return EDPVS_OK;
}
