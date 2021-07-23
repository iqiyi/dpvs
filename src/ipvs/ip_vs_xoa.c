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
 *
 * chennan.7733@bytedance.com, May 2020, initial.
 */
#include <assert.h>
#include "ipv4.h"
#include "ipv6.h"
#include "icmp.h"
#include "icmp6.h"
#include "ipvs/ipvs.h"
#include "ipvs/xoa.h"

static inline uint8_t __dp_vs_get_xoa_hdrtype(bool is_asym_trans)
{
    return is_asym_trans ? DPVS_XOA_HDRTYPE_ASYM : DPVS_XOA_HDRTYPE_SYM;
}

static inline bool dp_vs_xoa_exceed_mtu(uint32_t pkt_len, uint32_t mtu)
{
    if (pkt_len > mtu) {
        RTE_LOG(INFO, IPVS,
                "%s: need fragment, pkt len(%d) exceeds mtu(%d)\n",
                __func__, pkt_len, mtu);
        return true;
    }

    return false;
}

/*
 * "xoa" is only applied to fnat46 and fnat66 modes.
 */
int dp_vs_xoa_get_iplen(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
                        int *iphdr_len, int *iptot_len, int *xoa_len,
                        uint32_t mtu)
{
    int pkt_len; /* the final packet length */

    if (dp_vs_conn_is_nat66(conn)) {
        struct ip6_hdr *ip6h = ip6_hdr(mbuf);
        /*
         * iphdr_len:
         *   IPv6 header length (40 bytes) + ext header length
         * iptot_len:
         *   IPv6 header length (40 bytes) + ext header length + payload length
         */
        *iphdr_len = ip6_hdrlen(mbuf);

        if (*iphdr_len != sizeof(struct rte_ipv6_hdr)) {
            return EDPVS_INVPKT;
        }

        *xoa_len   = DPVS_XOA_HDRLEN_V6;
        *iptot_len = sizeof(struct ip6_hdr) + ntohs(ip6h->ip6_plen);

        pkt_len = mbuf->pkt_len + (*xoa_len);

    } else if (dp_vs_conn_is_nat46(conn)) {
        struct rte_ipv4_hdr *ip4h = ip4_hdr(mbuf);

        *xoa_len   = DPVS_XOA_HDRLEN_V4;
        *iphdr_len = ip4_hdrlen(mbuf);
        *iptot_len = ntohs(ip4h->total_length);

        pkt_len = (*iptot_len) - (*iphdr_len)
                    + sizeof(struct ip6_hdr) + (*xoa_len);
    } else {
        return EDPVS_NOTSUPP;
    }

    if (dp_vs_xoa_exceed_mtu(pkt_len, mtu)) {
        return EDPVS_FRAG;
    }

    return EDPVS_OK;
}

/*
 * Always move the shorter part that means moving the IP fixed header (excluding
 * ip option) in order to insert xoa header if the header is shorter than the
 * payload. Otherwise, move the payload (IP option, tcp/udp header and payload)
 * for the same purpose.
 */
void *dp_vs_xoa_insert(struct rte_mbuf *mbuf, void *iph,
                       int iptot_len, int iphdr_len, int xoa_len)
{
    void *niph;

    assert(mbuf && iph);

    /* the IP header is shorter than the left part so move the IP header */
    if (likely(iptot_len >= (iphdr_len << 1))) {
        niph = (void *)rte_pktmbuf_prepend(mbuf, xoa_len);
        if (unlikely(!niph)) {
            RTE_LOG(INFO, IPVS,
                    "%s: mbuf does not have enough header room.\n",
                    __func__);
            return NULL;
        }

        memmove(niph, iph, iphdr_len);
    } else {
        void *p = NULL;

        niph = iph;

        /* pull all bits in segments to first segment */
        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)) {
            RTE_LOG(INFO, IPVS,
                    "%s: mbuf do not have enough room.\n",
                    __func__);
            return NULL;
        }

        p = (void *)rte_pktmbuf_append(mbuf, xoa_len);
        if (unlikely(!p)) {
            RTE_LOG(INFO, IPVS,
                    "%s: mbuf do not have enough tail room.\n",
                    __func__);
            return NULL;
        }

        memmove(iph + iphdr_len + xoa_len,
                iph + iphdr_len, iptot_len - iphdr_len);
    }

    return niph;
}

void dp_vs_xoa4_fill(struct dp_vs_xoa_hdr *xoah, int af,
                     union inet_addr *saddr, union inet_addr *daddr,
                     uint16_t sport, uint16_t dport, bool is_asym_trans)
{
    xoah->ipv4_type    = __dp_vs_get_xoa_hdrtype(is_asym_trans);
    xoah->ipv4_padding = 0;
    xoah->sport = sport;
    xoah->dport = dport;

    if (af == AF_INET6) {
        xoah->ipv4_length    = DPVS_XOA_HDRLEN_V6;
        xoah->ipv4_operation = 1;
        xoah->ipv6_saddr     = saddr->in6;
        xoah->ipv6_daddr     = daddr->in6;
    } else {
        xoah->ipv4_length    = DPVS_XOA_HDRLEN_V4;
        xoah->ipv4_operation = 0;
        xoah->ipv4_saddr     = saddr->in;
        xoah->ipv4_daddr     = daddr->in;
    }
}

void dp_vs_xoa6_fill(struct dp_vs_xoa_hdr *xoah, int af,
                     union inet_addr *saddr, union inet_addr *daddr,
                     uint16_t sport, uint16_t dport,
                     uint8_t next_proto, bool is_asym_trans)
{
    xoah->ipv6_nexthdr = next_proto;
    xoah->ipv6_option  = __dp_vs_get_xoa_hdrtype(is_asym_trans);
    xoah->sport = sport;
    xoah->dport = dport;

    if (af == AF_INET6) {
        xoah->ipv6_hdrlen = (DPVS_XOA_HDRLEN_V6 >> 3) - 1;
        xoah->ipv6_optlen = DPVS_XOA_HDRLEN_V6 - 4;
        xoah->ipv6_saddr  = saddr->in6;
        xoah->ipv6_daddr  = daddr->in6;
    } else {
        xoah->ipv6_hdrlen = (DPVS_XOA_HDRLEN_V4 >> 3) - 1;
        xoah->ipv6_optlen = DPVS_XOA_HDRLEN_V4 - 4;
        xoah->ipv4_saddr  = saddr->in;
        xoah->ipv4_daddr  = daddr->in;
    }
}
