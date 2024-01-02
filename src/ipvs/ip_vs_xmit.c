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
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <assert.h>
#include "dpdk.h"
#include "ipv4.h"
#include "ipv6.h"
#include "route.h"
#include "route6.h"
#include "icmp.h"
#include "icmp6.h"
#include "neigh.h"
#include "ipvs/xmit.h"
#include "ipvs/nat64.h"
#include "parser/parser.h"

static bool fast_xmit_close = false;
static bool xmit_ttl = false;

static int __dp_vs_fast_xmit_fnat4(struct dp_vs_proto *proto,
                                   struct dp_vs_conn *conn,
                                   struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *ip4h = ip4_hdr(mbuf);
    struct rte_ether_hdr *eth;
    uint16_t packet_type = RTE_ETHER_TYPE_IPV4;
    int err;

    if (unlikely(conn->in_dev == NULL))
        return EDPVS_NOROUTE;

    if (unlikely(rte_is_zero_ether_addr(&conn->in_dmac) ||
                 rte_is_zero_ether_addr(&conn->in_smac)))
        return EDPVS_NOTSUPP;

    /* pre-handler before translation */
    if (proto->fnat_in_pre_handler) {
        err = proto->fnat_in_pre_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            return err;

        /*
         * re-fetch IP header
         * the offset may changed during pre-handler
         */
        ip4h = ip4_hdr(mbuf);
    }

    ip4h->hdr_checksum = 0;
    ip4h->src_addr = conn->laddr.in.s_addr;
    ip4h->dst_addr = conn->daddr.in.s_addr;

    if(proto->fnat_in_handler) {
        err = proto->fnat_in_handler(proto, conn, mbuf);
        if(err != EDPVS_OK)
            return err;
        ip4h = ip4_hdr(mbuf);
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        ip4h->hdr_checksum = 0;
    } else {
        ip4_send_csum(ip4h);
    }

    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf,
                    (uint16_t)sizeof(struct rte_ether_hdr));
    rte_ether_addr_copy(&conn->in_dmac, &eth->d_addr);
    rte_ether_addr_copy(&conn->in_smac, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(packet_type);
    mbuf->packet_type = packet_type;

    err = netif_xmit(mbuf, conn->in_dev);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to netif_xmit.\n", __func__);

    /* must return OK since netif_xmit alway consume mbuf */
    return EDPVS_OK;
}

static int __dp_vs_fast_xmit_fnat6(struct dp_vs_proto *proto,
                                   struct dp_vs_conn *conn,
                                   struct rte_mbuf *mbuf)
{
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct rte_ether_hdr *eth;
    uint16_t packet_type = RTE_ETHER_TYPE_IPV6;
    int err;

    if (unlikely(conn->in_dev == NULL))
        return EDPVS_NOROUTE;

    if (unlikely(rte_is_zero_ether_addr(&conn->in_dmac) ||
                 rte_is_zero_ether_addr(&conn->in_smac)))
        return EDPVS_NOTSUPP;

    /* pre-handler before translation */
    if (proto->fnat_in_pre_handler) {
        err = proto->fnat_in_pre_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            return err;

        /*
         * re-fetch IP header
         * the offset may changed during pre-handler
         */
        ip6h = ip6_hdr(mbuf);
    }

    ip6h->ip6_src = conn->laddr.in6;
    ip6h->ip6_dst = conn->daddr.in6;

    if(proto->fnat_in_handler) {
        err = proto->fnat_in_handler(proto, conn, mbuf);
        if(err != EDPVS_OK)
            return err;
    }

    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf,
                    (uint16_t)sizeof(struct rte_ether_hdr));
    rte_ether_addr_copy(&conn->in_dmac, &eth->d_addr);
    rte_ether_addr_copy(&conn->in_smac, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(packet_type);
    mbuf->packet_type = packet_type;

    err = netif_xmit(mbuf, conn->in_dev);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to netif_xmit.\n", __func__);

    /* must return OK since netif_xmit alway consume mbuf */
    return EDPVS_OK;
}

static int dp_vs_fast_xmit_fnat(int af,
                                struct dp_vs_proto *proto,
                                struct dp_vs_conn *conn,
                                struct rte_mbuf *mbuf)
{
    return af == AF_INET ? __dp_vs_fast_xmit_fnat4(proto, conn, mbuf)
        : __dp_vs_fast_xmit_fnat6(proto, conn, mbuf);
}

static int __dp_vs_fast_outxmit_fnat4(struct dp_vs_proto *proto,
                                      struct dp_vs_conn *conn,
                                      struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *ip4h = ip4_hdr(mbuf);
    struct rte_ether_hdr *eth;
    uint16_t packet_type = RTE_ETHER_TYPE_IPV4;
    int err;

    if (unlikely(conn->out_dev == NULL))
        return EDPVS_NOROUTE;

    if (unlikely(rte_is_zero_ether_addr(&conn->out_dmac) ||
                 rte_is_zero_ether_addr(&conn->out_smac)))
        return EDPVS_NOTSUPP;

    /* pre-handler before translation */
    if (proto->fnat_out_pre_handler) {
        err = proto->fnat_out_pre_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            return err;

        /*
         * re-fetch IP header
         * the offset may changed during pre-handler
         */
        ip4h = ip4_hdr(mbuf);
    }

    ip4h->hdr_checksum = 0;
    ip4h->src_addr = conn->vaddr.in.s_addr;
    ip4h->dst_addr = conn->caddr.in.s_addr;

    if(proto->fnat_out_handler) {
        err = proto->fnat_out_handler(proto, conn, mbuf);
        if(err != EDPVS_OK)
            return err;
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        ip4h->hdr_checksum = 0;
    } else {
        ip4_send_csum(ip4h);
    }

    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf,
                    (uint16_t)sizeof(struct rte_ether_hdr));
    rte_ether_addr_copy(&conn->out_dmac, &eth->d_addr);
    rte_ether_addr_copy(&conn->out_smac, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(packet_type);
    mbuf->packet_type = packet_type;

    err = netif_xmit(mbuf, conn->out_dev);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to netif_xmit.\n", __func__);

    /* must return OK since netif_xmit alway consume mbuf */
    return EDPVS_OK;
}

static int __dp_vs_fast_outxmit_fnat6(struct dp_vs_proto *proto,
                                      struct dp_vs_conn *conn,
                                      struct rte_mbuf *mbuf)
{
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct rte_ether_hdr *eth;
    uint16_t packet_type = RTE_ETHER_TYPE_IPV6;
    int err;

    if (unlikely(conn->out_dev == NULL))
        return EDPVS_NOROUTE;

    if (unlikely(rte_is_zero_ether_addr(&conn->out_dmac) ||
                 rte_is_zero_ether_addr(&conn->out_smac)))
        return EDPVS_NOTSUPP;

    /* pre-handler before translation */
    if (proto->fnat_out_pre_handler) {
        err = proto->fnat_out_pre_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            return err;

        /*
         * re-fetch IP header
         * the offset may changed during pre-handler
         */
        ip6h = ip6_hdr(mbuf);
    }

    ip6h->ip6_src = conn->vaddr.in6;
    ip6h->ip6_dst = conn->caddr.in6;

    if(proto->fnat_out_handler) {
        err = proto->fnat_out_handler(proto, conn, mbuf);
        if(err != EDPVS_OK)
            return err;
    }

    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf,
                    (uint16_t)sizeof(struct rte_ether_hdr));
    rte_ether_addr_copy(&conn->out_dmac, &eth->d_addr);
    rte_ether_addr_copy(&conn->out_smac, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(packet_type);
    mbuf->packet_type = packet_type;

    err = netif_xmit(mbuf, conn->out_dev);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to netif_xmit.\n", __func__);

    /* must return OK since netif_xmit alway consume mbuf */
    return EDPVS_OK;
}

static int dp_vs_fast_outxmit_fnat(int af,
                          struct dp_vs_proto *proto,
                          struct dp_vs_conn *conn,
                          struct rte_mbuf *mbuf)
{
    return af == AF_INET ? __dp_vs_fast_outxmit_fnat4(proto, conn, mbuf)
        : __dp_vs_fast_outxmit_fnat6(proto, conn, mbuf);
}

/*
 * ARP_HDR_ETHER SUPPORT ONLY
 * save source mac(client) for output in conn as dest mac
 */
static void dp_vs_save_xmit_info(struct rte_mbuf *mbuf,
                          struct dp_vs_proto *proto,
                          struct dp_vs_conn *conn)
{
    struct rte_ether_hdr *eth = NULL;
    struct netif_port *port = NULL;

    if (!rte_is_zero_ether_addr(&conn->out_dmac) &&
        !rte_is_zero_ether_addr(&conn->out_smac))
        return;

    if (unlikely(mbuf->l2_len != sizeof(struct rte_ether_hdr)))
        return;

    port = netif_port_get(mbuf->port);
    if (port)
        conn->out_dev = port;

    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, mbuf->l2_len);

    rte_ether_addr_copy(&eth->s_addr, &conn->out_dmac);
    rte_ether_addr_copy(&eth->d_addr, &conn->out_smac);

    rte_pktmbuf_adj(mbuf, sizeof(struct rte_ether_hdr));
}

/*
 * save source mac(rs) for input in conn as dest mac
 */
static void dp_vs_save_outxmit_info(struct rte_mbuf *mbuf,
                             struct dp_vs_proto *proto,
                             struct dp_vs_conn *conn)
{
    struct rte_ether_hdr *eth = NULL;
    struct netif_port *port = NULL;

    if (!rte_is_zero_ether_addr(&conn->in_dmac) &&
        !rte_is_zero_ether_addr(&conn->in_smac))
        return;

    if (mbuf->l2_len != sizeof(struct rte_ether_hdr))
        return;

    port = netif_port_get(mbuf->port);
    if (port)
        conn->in_dev = port;

    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, mbuf->l2_len);

    rte_ether_addr_copy(&eth->s_addr, &conn->in_dmac);
    rte_ether_addr_copy(&eth->d_addr, &conn->in_smac);

    rte_pktmbuf_adj(mbuf, sizeof(struct rte_ether_hdr));
}

/*
 * in: route to rs
 * out:route to client
 */
static void dp_vs_conn_cache_rt(struct dp_vs_conn *conn, struct route_entry *rt, bool in)
{
    if ((in && conn->in_dev && (conn->in_nexthop.in.s_addr != htonl(INADDR_ANY))) ||
        (!in && conn->out_dev && (conn->out_nexthop.in.s_addr != htonl(INADDR_ANY))))
        return;

    if (in) {
        conn->in_dev = rt->port;
        if (rt->gw.s_addr == htonl(INADDR_ANY)) {
            conn->in_nexthop.in = conn->daddr.in;
        } else {
            conn->in_nexthop.in = rt->gw;
        }

    } else {
        conn->out_dev = rt->port;
        if (rt->gw.s_addr == htonl(INADDR_ANY)) {
            conn->out_nexthop.in = conn->caddr.in;
        } else {
            conn->out_nexthop.in = rt->gw;
        }
    }
}

static void dp_vs_conn_cache_rt6(struct dp_vs_conn *conn, struct route6 *rt, bool in)
{
    if ((in && conn->in_dev && !ipv6_addr_any(&conn->in_nexthop.in6)) ||
        (!in && conn->out_dev && !ipv6_addr_any(&conn->out_nexthop.in6)))
        return;

    if (in) {
        conn->in_dev = rt->rt6_dev;
        if (ipv6_addr_any(&rt->rt6_gateway)) {
            conn->in_nexthop.in6 = conn->daddr.in6;
        } else {
            conn->in_nexthop.in6 = rt->rt6_gateway;
        }

    } else {
        conn->out_dev = rt->rt6_dev;
        if (ipv6_addr_any(&rt->rt6_gateway)) {
            conn->out_nexthop.in6 = conn->caddr.in6;
        } else {
            conn->out_nexthop.in6 = rt->rt6_gateway;
        }
    }
}

static int __dp_vs_xmit_fnat4(struct dp_vs_proto *proto,
                              struct dp_vs_conn *conn,
                              struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    int err, mtu;

    if (!fast_xmit_close && !(conn->flags & DPVS_CONN_F_NOFASTXMIT)) {
        dp_vs_save_xmit_info(mbuf, proto, conn);
        if (!dp_vs_fast_xmit_fnat(AF_INET, proto, conn, mbuf)) {
            return EDPVS_OK;
        }
    }

    /*
     * drop old route. just for safe, because
     * FNAT is PRE_ROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: FNAT have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
        route4_put(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr = conn->daddr.in;
    fl4.fl4_saddr = conn->laddr.in;
    fl4.fl4_tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    /*
     * didn't cache the pointer to rt
     * or route can't be deleted when there is conn ref
     * this is for neighbour confirm
     */
    dp_vs_conn_cache_rt(conn, rt, true);

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, htonl(mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(iph->time_to_live <= 1)) {
            icmp_send(mbuf, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        iph->time_to_live--;
    }

    /* pre-handler before translation */
    if (proto->fnat_in_pre_handler) {
        err = proto->fnat_in_pre_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;

        /*
         * re-fetch IP header
         * the offset may changed during pre-handler
         */
        iph = ip4_hdr(mbuf);
    }

    /* L3 translation before l4 re-csum */
    iph->hdr_checksum = 0;
    iph->src_addr = conn->laddr.in.s_addr;
    iph->dst_addr = conn->daddr.in.s_addr;

    /* L4 FNAT translation */
    if (proto->fnat_in_handler) {
        err = proto->fnat_in_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
        iph = ip4_hdr(mbuf);
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int __dp_vs_xmit_fnat6(struct dp_vs_proto *proto,
                              struct dp_vs_conn *conn,
                              struct rte_mbuf *mbuf)
{
    struct flow6 fl6;
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct route6 *rt6;
    int err, mtu;

    if (!fast_xmit_close && !(conn->flags & DPVS_CONN_F_NOFASTXMIT)) {
        dp_vs_save_xmit_info(mbuf, proto, conn);
        if (!dp_vs_fast_xmit_fnat(AF_INET6, proto, conn, mbuf)) {
            return EDPVS_OK;
        }
    }

    /*
     * drop old route. just for safe, because
     * FNAT is PRE_ROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: FNAT have route %p ?\n",
                __func__, MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
        route6_put(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
    }

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_daddr = conn->daddr.in6;
    fl6.fl6_saddr = conn->laddr.in6;
    rt6 = route6_output(mbuf, &fl6);
    if (!rt6) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    /*
     * didn't cache the pointer to rt6
     * or route can't be deleted when there is conn ref
     * this is for neighbour confirm.
     */
    dp_vs_conn_cache_rt6(conn, rt6, true);

    // check mtu
    mtu = rt6->rt6_mtu;
    if (mbuf->pkt_len > mtu) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu);

        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(ip6h->ip6_hops <= 1)) {
            icmp6_send(mbuf, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        ip6h->ip6_hops--;
    }

    /* pre-handler before translation */
    if (proto->fnat_in_pre_handler) {
        err = proto->fnat_in_pre_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;

        /*
         * re-fetch IP header
         * the offset may changed during pre-handler
         */
        ip6h = ip6_hdr(mbuf);
    }

    /* L3 translation before l4 re-csum */
    ip6h->ip6_src = conn->laddr.in6;
    ip6h->ip6_dst = conn->daddr.in6;

    /* L4 FNAT translation */
    if (proto->fnat_in_handler) {
        err = proto->fnat_in_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt6->rt6_dev, ip6_output);

errout:
    if (rt6)
        route6_put(rt6);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int __dp_vs_xmit_fnat64(struct dp_vs_proto *proto,
                               struct dp_vs_conn *conn,
                               struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct rte_ipv4_hdr *ip4h;
    uint32_t pkt_len;
    struct route_entry *rt;
    int err, mtu;

    /*
     * drop old route. just for safe, because
     * FNAT is PRE_ROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: FNAT have route %p ?\n",
                __func__, MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
        route6_put(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr = conn->daddr.in;
    fl4.fl4_saddr = conn->laddr.in;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    /*
     * didn't cache the pointer to rt
     * or route can't be deleted when there is conn ref
     * this is for neighbour confirm
     */
    dp_vs_conn_cache_rt(conn, rt, true);

    /*
     * mbuf is from IPv6, icmp should send by icmp6
     * ext_hdr and
     */
    mtu = rt->mtu;
    pkt_len = mbuf_nat6to4_len(mbuf);
    if (pkt_len > mtu) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu);

        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;
    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(ip6h->ip6_hops <= 1)) {
            icmp6_send(mbuf, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
            err = EDPVS_DROP;
            goto errout;
        }
        ip6h->ip6_hops--;
    }

    /* pre-handler before translation */
    if (proto->fnat_in_pre_handler) {
        err = proto->fnat_in_pre_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    /* L3 translation before l4 re-csum */
    err = mbuf_6to4(mbuf, &conn->laddr.in, &conn->daddr.in);
    if (err)
        goto errout;
    ip4h = ip4_hdr(mbuf);
    ip4h->hdr_checksum = 0;

    /* L4 FNAT translation */
    if (proto->fnat_in_handler) {
        err = proto->fnat_in_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
        ip4h = ip4_hdr(mbuf);
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        ip4h->hdr_checksum = 0;
    } else {
        ip4_send_csum(ip4h);
    }

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

int dp_vs_xmit_fnat(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    int af = conn->af;
    assert(af == AF_INET || af == AF_INET6);

    if (tuplehash_in(conn).af == AF_INET &&
        tuplehash_out(conn).af == AF_INET)
        return __dp_vs_xmit_fnat4(proto, conn, mbuf);
    if (tuplehash_in(conn).af == AF_INET6 &&
        tuplehash_out(conn).af == AF_INET6)
        return __dp_vs_xmit_fnat6(proto, conn, mbuf);
    if (tuplehash_in(conn).af == AF_INET6 &&
        tuplehash_out(conn).af == AF_INET)
        return __dp_vs_xmit_fnat64(proto, conn, mbuf);

    rte_pktmbuf_free(mbuf);
    return EDPVS_NOTSUPP;
}

static int __dp_vs_out_xmit_fnat4(struct dp_vs_proto *proto,
                                  struct dp_vs_conn *conn,
                                  struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    int err, mtu;

    if (!fast_xmit_close && !(conn->flags & DPVS_CONN_F_NOFASTXMIT)) {
        dp_vs_save_outxmit_info(mbuf, proto, conn);
        if (!dp_vs_fast_outxmit_fnat(AF_INET, proto, conn, mbuf)) {
            return EDPVS_OK;
        }
    }

    /*
     * drop old route. just for safe, because
     * FNAT is PRE_ROUTING, should not have route.
     */
    if (MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) != NULL)
        route4_put(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr = conn->caddr.in;
    fl4.fl4_saddr = conn->vaddr.in;
    fl4.fl4_tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    /*
     * didn't cache the pointer to rt
     * or route can't be deleted when there is conn ref
     * this is for neighbour confirm
     */
    dp_vs_conn_cache_rt(conn, rt, false);

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, htonl(mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(iph->time_to_live <= 1)) {
            icmp_send(mbuf, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        iph->time_to_live--;
    }

    /* pre-handler before translation */
    if (proto->fnat_out_pre_handler) {
        err = proto->fnat_out_pre_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;

        /*
         * re-fetch IP header
         * the offset may changed during pre-handler
         */
        iph = ip4_hdr(mbuf);
    }

    /* L3 translation before l4 re-csum */
    iph->hdr_checksum = 0;
    iph->src_addr = conn->vaddr.in.s_addr;
    iph->dst_addr = conn->caddr.in.s_addr;

    /* L4 FNAT translation */
    if (proto->fnat_out_handler) {
        err = proto->fnat_out_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int __dp_vs_out_xmit_fnat6(struct dp_vs_proto *proto,
                                  struct dp_vs_conn *conn,
                                  struct rte_mbuf *mbuf)
{
    struct flow6 fl6;
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct route6 *rt6;
    int err, mtu;

    if (!fast_xmit_close && !(conn->flags & DPVS_CONN_F_NOFASTXMIT)) {
        dp_vs_save_outxmit_info(mbuf, proto, conn);
        if (!dp_vs_fast_outxmit_fnat(AF_INET6, proto, conn, mbuf)) {
            return EDPVS_OK;
        }
    }

    /*
     * drop old route. just for safe, because
     * FNAT is PRE_ROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL))
        route6_put(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_daddr = conn->caddr.in6;
    fl6.fl6_saddr = conn->vaddr.in6;
    rt6 = route6_output(mbuf, &fl6);
    if (!rt6) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    /*
     * didn't cache the pointer to rt
     * or route can't be deleted when there is conn ref
     * this is for neighbour confirm.
     */
    dp_vs_conn_cache_rt6(conn, rt6, false);

    mtu = rt6->rt6_mtu;
    if (mbuf->pkt_len > mtu) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu);
        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(ip6h->ip6_hops <= 1)) {
            icmp6_send(mbuf, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        ip6h->ip6_hops--;
    }

    /* pre-handler before translation */
    if (proto->fnat_out_pre_handler) {
        err = proto->fnat_out_pre_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;

        /*
         * re-fetch IP header
         * the offset may changed during pre-handler
         */
        ip6h = ip6_hdr(mbuf);
    }

    /* L3 translation before l4 re-csum */
    ip6h->ip6_src = conn->vaddr.in6;
    ip6h->ip6_dst = conn->caddr.in6;

    /* L4 FNAT translation */
    if (proto->fnat_out_handler) {
        err = proto->fnat_out_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt6->rt6_dev, ip6_output);

errout:
    if (rt6)
        route6_put(rt6);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int __dp_vs_out_xmit_fnat46(struct dp_vs_proto *proto,
                                   struct dp_vs_conn *conn,
                                   struct rte_mbuf *mbuf)
{
    struct flow6 fl6;
    struct rte_ipv4_hdr *ip4h = ip4_hdr(mbuf);
    uint32_t pkt_len;
    struct route6 *rt6;
    int err, mtu;

    /*
     * drop old route. just for safe, because
     * FNAT is PRE_ROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: FNAT have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
        route4_put(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
    }

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_daddr = conn->caddr.in6;
    fl6.fl6_saddr = conn->vaddr.in6;
    rt6 = route6_output(mbuf, &fl6);
    if (!rt6) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    /*
     * didn't cache the pointer to rt
     * or route can't be deleted when there is conn ref
     * this is for neighbour confirm
     */
    dp_vs_conn_cache_rt6(conn, rt6, false);

    /*
     * mbuf is from IPv6, icmp should send by icmp6
     * ext_hdr and
     */
    mtu = rt6->rt6_mtu;
    pkt_len = mbuf_nat4to6_len(mbuf);
    if (pkt_len > mtu
           && (ip4h->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, htonl(mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;
    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(ip4h->time_to_live <= 1)) {
            icmp_send(mbuf, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
            err = EDPVS_DROP;
            goto errout;
        }
        ip4h->time_to_live--;
    }

    /* pre-handler before translation */
    if (proto->fnat_out_pre_handler) {
        err = proto->fnat_out_pre_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    /* L3 translation before l4 re-csum */
    err = mbuf_4to6(mbuf, &conn->vaddr.in6, &conn->caddr.in6);
    if (err)
        goto errout;

    /* L4 FNAT translation */
    if (proto->fnat_out_handler) {
        err = proto->fnat_out_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt6->rt6_dev, ip6_output);

errout:
    if (rt6)
        route6_put(rt6);
    rte_pktmbuf_free(mbuf);
    return err;
}

int dp_vs_out_xmit_fnat(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf)
{
    int af = conn->af;
    assert(af == AF_INET || af == AF_INET6);

    if (tuplehash_in(conn).af == AF_INET &&
        tuplehash_out(conn).af == AF_INET)
        return __dp_vs_out_xmit_fnat4(proto, conn, mbuf);
    if (tuplehash_in(conn).af == AF_INET6 &&
        tuplehash_out(conn).af == AF_INET6)
        return __dp_vs_out_xmit_fnat6(proto, conn, mbuf);
    if (tuplehash_in(conn).af == AF_INET6 &&
        tuplehash_out(conn).af == AF_INET)
        return __dp_vs_out_xmit_fnat46(proto, conn, mbuf);

    rte_pktmbuf_free(mbuf);
    return EDPVS_NOTSUPP;
}

/* mbuf's data should pointer to outer IP packet. */
static void __dp_vs_xmit_icmp4(struct rte_mbuf *mbuf,
                               struct dp_vs_proto *prot,
                               struct dp_vs_conn *conn, int dir)
{
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct icmphdr *icmph = (struct icmphdr *)
                            ((unsigned char *)ip4_hdr(mbuf) + ip4_hdrlen(mbuf));
    struct rte_ipv4_hdr *ciph = (struct rte_ipv4_hdr *)(icmph + 1);
    int fullnat = (conn->dest->fwdmode == DPVS_FWD_MODE_FNAT);
    uint16_t csum;

    /*
     * outer/inner L3 translation.
     */
    if (fullnat) {
        if (dir == DPVS_CONN_DIR_INBOUND) {
            iph->src_addr = conn->laddr.in.s_addr;
            ciph->dst_addr = conn->laddr.in.s_addr;
        } else {
            iph->dst_addr = conn->caddr.in.s_addr;
            ciph->src_addr = conn->caddr.in.s_addr;
        }
    }

    if (dir == DPVS_CONN_DIR_INBOUND) {
        iph->dst_addr = conn->daddr.in.s_addr;
        ip4_send_csum(iph);
        ciph->src_addr = conn->daddr.in.s_addr;
        ip4_send_csum(ciph);
    } else {
        iph->src_addr = conn->vaddr.in.s_addr;
        ip4_send_csum(iph);
        ciph->dst_addr = conn->vaddr.in.s_addr;
        ip4_send_csum(ciph);
    }

    /*
     * inner L4 translation.
     *
     * note it's no way to recalc inner csum to lack of data,
     * actually it's not needed.
     */
    if (ciph->next_proto_id == IPPROTO_TCP
            || ciph->next_proto_id == IPPROTO_UDP) {
        uint16_t *ports = (void *)ciph + \
                          ((ciph->version_ihl & RTE_IPV4_HDR_IHL_MASK)<<2);

        if (fullnat) {
            if (dir == DPVS_CONN_DIR_INBOUND) {
                ports[1] = conn->lport;
            } else {
                ports[0] = conn->cport;
                /* seq adjustment (changed by FNAT) */
                if (ciph->next_proto_id == IPPROTO_TCP) {
                    uint32_t *seq = (uint32_t *)ports + 1;
                    *seq = htonl(ntohl(*seq) - conn->fnat_seq.delta);
                }
            }
        }

        if (dir == DPVS_CONN_DIR_INBOUND) {
            ports[0] = conn->dport;
            /* seq adjustment (changed by SynProxy) */
            if (ciph->next_proto_id == IPPROTO_TCP) {
                uint32_t *seq = (uint32_t *)ports + 1;
                *seq = htonl(ntohl(*seq) - conn->syn_proxy_seq.delta);
            }
        } else {
            ports[1] = conn->vport;
        }
    }

    /*
     * ICMP recalc csum.
     */
    icmph->checksum = 0;
    csum = rte_raw_cksum(icmph, mbuf->pkt_len - ip4_hdrlen(mbuf));
    icmph->checksum = (csum == 0xffff) ? csum : ~csum;

    return;
}

/* mbuf's data should pointer to outer IP packet. */
static void __dp_vs_xmit_icmp6(struct rte_mbuf *mbuf,
                               struct dp_vs_proto *prot,
                               struct dp_vs_conn *conn, int dir)
{
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct icmp6_hdr *icmp6h;
    struct ip6_hdr *cip6h;
    int fullnat = (conn->dest->fwdmode == DPVS_FWD_MODE_FNAT);
    uint8_t nexthdr = ip6h->ip6_nxt;
    int offset = sizeof(*ip6h);
    uint32_t csum, l4_len;

    offset = ip6_skip_exthdr(mbuf, offset, &nexthdr);
    if (offset < 0) {
        RTE_LOG(WARNING, IPVS, "%s: Get ipv6 payload fail, mbuf : %p \n",
                __func__, mbuf);
        return ;
    }

    if (unlikely(nexthdr != IPPROTO_ICMPV6)) {
        RTE_LOG(WARNING, IPVS, "%s: Get ipv6 payload isn't icmp, mbuf : %p \n",
                __func__, mbuf);
        return ;
    }

    icmp6h = (struct icmp6_hdr *)
            ((unsigned char *)ip6_hdr(mbuf) + offset);
    cip6h = (struct ip6_hdr *)(icmp6h + 1);
    /*
     * outer/inner L3 translation.
     */
    if (fullnat) {
        if (dir == DPVS_CONN_DIR_INBOUND) {
            ip6h->ip6_src = conn->laddr.in6;
            cip6h->ip6_dst = conn->laddr.in6;
        } else {
            ip6h->ip6_dst = conn->caddr.in6;
            cip6h->ip6_src = conn->caddr.in6;
        }
    }

    if (dir == DPVS_CONN_DIR_INBOUND) {
        ip6h->ip6_dst = conn->daddr.in6;
        cip6h->ip6_src = conn->daddr.in6;
    } else {
        ip6h->ip6_src = conn->vaddr.in6;
        cip6h->ip6_dst = conn->vaddr.in6;
    }

    /*
     * inner L4 translation.
     *
     * note it's no way to recalc inner csum to lack of data,
     * actually it's not needed.
     */
    offset += (sizeof(*icmp6h) + sizeof(*cip6h));
    nexthdr = cip6h->ip6_nxt;
    offset = ip6_skip_exthdr(mbuf, offset, &nexthdr);

    if (offset > 0
        && (nexthdr == IPPROTO_TCP
            || nexthdr == IPPROTO_UDP)) {
        uint16_t *ports = (void *)ip6_hdr(mbuf) + offset;

        if (fullnat) {
            if (dir == DPVS_CONN_DIR_INBOUND) {
                ports[1] = conn->lport;
            } else {
                ports[0] = conn->cport;
                /* seq adjustment (changed by FNAT) */
                if (nexthdr == IPPROTO_TCP) {
                    uint32_t *seq = (uint32_t *)ports + 1;
                    *seq = htonl(ntohl(*seq) - conn->fnat_seq.delta);
                }
            }
        }

        if (dir == DPVS_CONN_DIR_INBOUND) {
            ports[0] = conn->dport;
            /* seq adjustment (changed by SynProxy) */
            if (nexthdr == IPPROTO_TCP) {
                uint32_t *seq = (uint32_t *)ports + 1;
                *seq = htonl(ntohl(*seq) - conn->syn_proxy_seq.delta);
            }
        } else {
            ports[1] = conn->vport;
        }
    }

    /*
     * ICMP recalc csum.
     */
    icmp6h->icmp6_cksum = 0;
    l4_len = ntohs(ip6h->ip6_plen);
    csum = rte_raw_cksum(icmp6h, l4_len);
    csum += rte_ipv6_phdr_cksum((struct rte_ipv6_hdr *)ip6h, 0);

    csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
    csum = (~csum) & 0xffff;
    if (csum == 0)
        csum = 0xffff;

    icmp6h->icmp6_cksum = csum;

    return;
}

/* mbuf's data should pointer to outer IP packet. */
void dp_vs_xmit_icmp(struct rte_mbuf *mbuf,
                     struct dp_vs_proto *prot,
                     struct dp_vs_conn *conn, int dir)
{
    int af = conn->af;

    assert(af == AF_INET || af == AF_INET6);

    return af == AF_INET ? __dp_vs_xmit_icmp4(mbuf, prot, conn, dir)
        : __dp_vs_xmit_icmp6(mbuf, prot, conn, dir);
}

static int __dp_vs_xmit_dr4(struct dp_vs_proto *proto,
                            struct dp_vs_conn *conn,
                            struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    int err, mtu;

    if (unlikely(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: Already have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
        route4_put(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr.s_addr = conn->daddr.in.s_addr;
    fl4.fl4_saddr.s_addr = iph->src_addr;
    fl4.fl4_tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    /* dr xmit support cache of route to rs*/
    dp_vs_conn_cache_rt(conn, rt, true);

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, htonl(mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;
    err = neigh_output(AF_INET, (union inet_addr *)&conn->daddr.in, mbuf, rt->port);
    route4_put(rt);
    return err;

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int __dp_vs_xmit_dr6(struct dp_vs_proto *proto,
                            struct dp_vs_conn *conn,
                            struct rte_mbuf *mbuf)
{
    struct flow6 fl6;
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct route6 *rt6;
    int err, mtu;

    if (unlikely(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: Already have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
        route6_put(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
    }

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_daddr = conn->daddr.in6;
    fl6.fl6_saddr = ip6h->ip6_src;
    rt6 = route6_output(mbuf, &fl6);
    if (!rt6) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    /* dr xmit support cache of route to rs*/
    dp_vs_conn_cache_rt6(conn, rt6, true);

    mtu = rt6->rt6_mtu;
    if (mbuf->pkt_len > mtu) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu);
        err = EDPVS_FRAG;
        goto errout;
    }

    mbuf->packet_type = RTE_ETHER_TYPE_IPV6;
    err = neigh_output(AF_INET6, (union inet_addr *)&conn->daddr.in6, mbuf, rt6->rt6_dev);
    route6_put(rt6);
    return err;

errout:
    if (rt6)
        route6_put(rt6);
    rte_pktmbuf_free(mbuf);
    return err;
}

int dp_vs_xmit_dr(struct dp_vs_proto *proto,
                  struct dp_vs_conn *conn,
                  struct rte_mbuf *mbuf)
{
    int af = conn->af;

    assert(af == AF_INET || af == AF_INET6);

    return af == AF_INET ? __dp_vs_xmit_dr4(proto, conn, mbuf)
        : __dp_vs_xmit_dr6(proto, conn, mbuf);
}

static int __dp_vs_xmit_snat4(struct dp_vs_proto *proto,
                              struct dp_vs_conn *conn,
                              struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    int err, mtu;

    /*
     * drop old route. just for safe, because
     * inbound SNAT traffic is hooked at PRE_ROUTING,
     * should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: SNAT have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
        route4_put(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
    }

    /*
     * hosts inside SNAT may belongs to diff net,
     * let's route it.
     */
    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr = conn->daddr.in;
    fl4.fl4_saddr = conn->caddr.in;
    fl4.fl4_tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    dp_vs_conn_cache_rt(conn, rt, true);

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, htonl(mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(iph->time_to_live <= 1)) {
            icmp_send(mbuf, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        iph->time_to_live--;
    }

    /* L3 translation before l4 re-csum */
    iph->hdr_checksum = 0;
    iph->dst_addr = conn->daddr.in.s_addr;

    /* L4 translation */
    if (proto->snat_in_handler) {
        err = proto->snat_in_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    /* L3 re-checksum */
    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM))
        iph->hdr_checksum = 0;
    else
        ip4_send_csum(iph);

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int __dp_vs_xmit_snat6(struct dp_vs_proto *proto,
                              struct dp_vs_conn *conn,
                              struct rte_mbuf *mbuf)
{
    struct flow6 fl6;
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct route6 *rt6;
    int err, mtu;

    /*
     * drop old route. just for safe, because
     * inbound SNAT traffic is hooked at PRE_ROUTING,
     * should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: SNAT have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route6*, MBUF_FIELD_ROUTE));
        route6_put(MBUF_USERDATA(mbuf, struct route6*, MBUF_FIELD_ROUTE));
    }

    /*
     * hosts inside SNAT may belongs to diff net,
     * let's route it.
     */
    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_daddr = conn->daddr.in6;
    fl6.fl6_saddr = conn->caddr.in6;
    rt6 = route6_output(mbuf, &fl6);
    if (!rt6) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    dp_vs_conn_cache_rt6(conn, rt6, true);

    mtu = rt6->rt6_mtu;
    if (mbuf->pkt_len > mtu) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu);
        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(ip6h->ip6_hops <= 1)) {
            icmp6_send(mbuf, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        ip6h->ip6_hops--;
    }

    /* L3 translation before l4 re-csum */
    ip6h->ip6_dst = conn->daddr.in6;

    /* L4 translation */
    if (proto->snat_in_handler) {
        err = proto->snat_in_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt6->rt6_dev, ip6_output);

errout:
    if (rt6)
        route6_put(rt6);
    rte_pktmbuf_free(mbuf);
    return err;
}

int dp_vs_xmit_snat(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    int af = conn->af;

    assert(af == AF_INET || af == AF_INET6);

    return af == AF_INET ? __dp_vs_xmit_snat4(proto, conn, mbuf)
        : __dp_vs_xmit_snat6(proto, conn, mbuf);
}

static int __dp_vs_out_xmit_snat4(struct dp_vs_proto *proto,
                                  struct dp_vs_conn *conn,
                                  struct rte_mbuf *mbuf)
{
    int err;
    struct flow4 fl4;
    struct route_entry *rt = MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE);
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);

    if (!rt) {
        memset(&fl4, 0, sizeof(struct flow4));
        fl4.fl4_daddr = conn->caddr.in;
        fl4.fl4_saddr = conn->vaddr.in;
        fl4.fl4_tos = iph->type_of_service;

        rt = route4_output(&fl4);
        if (!rt) {
            err = EDPVS_NOROUTE;
            goto errout;
        }
        MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

        dp_vs_conn_cache_rt(conn, rt, false);
    }

    if (mbuf->pkt_len > rt->mtu &&
            (iph->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                  htonl(rt->mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(iph->time_to_live <= 1)) {
            icmp_send(mbuf, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        iph->time_to_live--;
    }

    /* L3 translation before L4 re-csum */
    iph->hdr_checksum = 0;
    iph->src_addr = conn->vaddr.in.s_addr;

    /* L4 translation */
    if (proto->snat_out_handler) {
        err = proto->snat_out_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    /* L3 re-checksum */
    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM))
        iph->hdr_checksum = 0;
    else
        ip4_send_csum(iph);

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int dp_vs_fast_xmit_nat(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct rte_ether_hdr *eth;
    int err;

    if (unlikely(conn->in_dev == NULL))
        return EDPVS_NOROUTE;

    if (unlikely(rte_is_zero_ether_addr(&conn->in_dmac) ||
                 rte_is_zero_ether_addr(&conn->in_smac)))
        return EDPVS_NOTSUPP;

    iph->hdr_checksum = 0;
    iph->dst_addr = conn->daddr.in.s_addr;

    if (proto->nat_in_handler) {
        err = proto->nat_in_handler(proto, conn, mbuf);
        if(err != EDPVS_OK)
            return err;
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }

    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf,
                    (uint16_t)sizeof(struct rte_ether_hdr));
    rte_ether_addr_copy(&conn->in_dmac, &eth->d_addr);
    rte_ether_addr_copy(&conn->in_smac, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;

    err = netif_xmit(mbuf, conn->in_dev);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to netif_xmit.\n", __func__);

    /* must return OK since netif_xmit alway consume mbuf */
    return EDPVS_OK;
}

static int dp_vs_fast_outxmit_nat(struct dp_vs_proto *proto,
                          struct dp_vs_conn *conn,
                          struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct rte_ether_hdr *eth;
    int err;

    if (unlikely(conn->out_dev == NULL))
        return EDPVS_NOROUTE;

    if (unlikely(rte_is_zero_ether_addr(&conn->out_dmac) ||
                 rte_is_zero_ether_addr(&conn->out_smac)))
        return EDPVS_NOTSUPP;

    iph->hdr_checksum = 0;
    iph->src_addr = conn->vaddr.in.s_addr;

    if (proto->nat_out_handler) {
        err = proto->nat_out_handler(proto, conn, mbuf);
        if(err != EDPVS_OK)
            return err;
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }

    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf,
                    (uint16_t)sizeof(struct rte_ether_hdr));
    rte_ether_addr_copy(&conn->out_dmac, &eth->d_addr);
    rte_ether_addr_copy(&conn->out_smac, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;

    err = netif_xmit(mbuf, conn->out_dev);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to netif_xmit.\n", __func__);

    /* must return OK since netif_xmit alway consume mbuf */
    return EDPVS_OK;
}

static int __dp_vs_out_xmit_snat6(struct dp_vs_proto *proto,
                                  struct dp_vs_conn *conn,
                                  struct rte_mbuf *mbuf)
{
    int err;
    struct flow6 fl6;
    struct route6 *rt6 = MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE);
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);

    if (!rt6) {
        memset(&fl6, 0, sizeof(struct flow6));
        fl6.fl6_daddr = conn->caddr.in6;
        fl6.fl6_saddr = conn->vaddr.in6;
        rt6 = route6_output(mbuf, &fl6);
        if (!rt6) {
            err = EDPVS_NOROUTE;
            goto errout;
        }

        MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;

        dp_vs_conn_cache_rt6(conn, rt6, false);
    }

    if (mbuf->pkt_len > rt6->rt6_mtu) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, rt6->rt6_mtu);
        err = EDPVS_FRAG;
        goto errout;
    }

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(ip6h->ip6_hops <= 1)) {
            icmp6_send(mbuf, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        ip6h->ip6_hops--;
    }

    /* L3 translation before L4 re-csum */
    ip6h->ip6_src = conn->vaddr.in6;

    /* L4 translation */
    if (proto->snat_out_handler) {
        err = proto->snat_out_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt6->rt6_dev, ip6_output);

errout:
    if (rt6)
        route6_put(rt6);
    rte_pktmbuf_free(mbuf);
    return err;
}

int dp_vs_out_xmit_snat(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf)
{
    int af = conn->af;

    assert(af == AF_INET ||  af == AF_INET6);

    return af == AF_INET ? __dp_vs_out_xmit_snat4(proto, conn, mbuf)
        : __dp_vs_out_xmit_snat6(proto, conn, mbuf);
}

static int __dp_vs_xmit_nat4(struct dp_vs_proto *proto,
                             struct dp_vs_conn *conn,
                             struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    int err, mtu;

    if (!fast_xmit_close && !(conn->flags & DPVS_CONN_F_NOFASTXMIT)) {
        dp_vs_save_xmit_info(mbuf, proto, conn);
        if (!dp_vs_fast_xmit_nat(proto, conn, mbuf)) {
            return EDPVS_OK;
        }
    }

    /*
     * drop old route. just for safe, because
     * NAT is PREROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: NAT have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
        route4_put(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr = conn->daddr.in;
    fl4.fl4_saddr = conn->caddr.in;
    fl4.fl4_tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    dp_vs_conn_cache_rt(conn, rt, true);

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                  htonl(rt->mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(iph->time_to_live <= 1)) {
            icmp_send(mbuf, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        iph->time_to_live--;
    }

    /* L3 translation before l4 re-csum */
    iph->hdr_checksum = 0;
    iph->dst_addr = conn->daddr.in.s_addr;

    /* L4 NAT translation */
    if (proto->nat_in_handler) {
        err = proto->nat_in_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int __dp_vs_xmit_nat6(struct dp_vs_proto *proto,
                             struct dp_vs_conn *conn,
                             struct rte_mbuf *mbuf)
{
    struct flow6 fl6;
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct route6 *rt6;
    int err, mtu;

    /*
     * drop old route. just for safe, because
     * NAT is PREROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: NAT have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
        route6_put(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
    }

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_daddr = conn->daddr.in6;
    fl6.fl6_saddr = conn->caddr.in6;
    rt6 = route6_output(mbuf, &fl6);
    if (!rt6) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    dp_vs_conn_cache_rt6(conn, rt6, true);

    mtu = rt6->rt6_mtu;
    if (mbuf->pkt_len > mtu) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu);
        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(ip6h->ip6_hops <= 1)) {
            icmp6_send(mbuf, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        ip6h->ip6_hops--;
    }

    /* L3 translation before l4 re-csum */
    ip6h->ip6_dst = conn->daddr.in6;

    /* L4 NAT translation */
    if (proto->nat_in_handler) {
        err = proto->nat_in_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt6->rt6_dev, ip6_output);

errout:
    if (rt6)
        route6_put(rt6);
    rte_pktmbuf_free(mbuf);
    return err;
}

int dp_vs_xmit_nat(struct dp_vs_proto *proto,
                   struct dp_vs_conn *conn,
                   struct rte_mbuf *mbuf)
{
    int af = conn->af;

    assert(af == AF_INET ||  af == AF_INET6);

    return af == AF_INET ? __dp_vs_xmit_nat4(proto, conn, mbuf)
        : __dp_vs_xmit_nat6(proto, conn, mbuf);
}

static int __dp_vs_out_xmit_nat4(struct dp_vs_proto *proto,
                                 struct dp_vs_conn *conn,
                                 struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    int err, mtu;

    if (!fast_xmit_close && !(conn->flags & DPVS_CONN_F_NOFASTXMIT)) {
        dp_vs_save_outxmit_info(mbuf, proto, conn);
        if (!dp_vs_fast_outxmit_nat(proto, conn, mbuf)) {
            return EDPVS_OK;
        }
    }

    /*
     * drop old route. just for safe, because
     * NAT is PREROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: NAT have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
        route4_put(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr = conn->caddr.in;
    fl4.fl4_saddr = conn->vaddr.in;
    fl4.fl4_tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    dp_vs_conn_cache_rt(conn, rt, false);

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                  htonl(rt->mtu));

        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(iph->time_to_live <= 1)) {
            icmp_send(mbuf, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        iph->time_to_live--;
    }

    /* L3 translation before l4 re-csum */
    iph->hdr_checksum = 0;
    iph->src_addr = conn->vaddr.in.s_addr;

    /* L4 NAT translation */
    if (proto->nat_out_handler) {
        err = proto->nat_out_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int __dp_vs_out_xmit_nat6(struct dp_vs_proto *proto,
                                 struct dp_vs_conn *conn,
                                 struct rte_mbuf *mbuf)
{
    struct flow6 fl6;
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct route6 *rt6;
    int err, mtu;

    /*
     * drop old route. just for safe, because
     * NAT is PREROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: NAT have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
        route6_put(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
    }

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_daddr = conn->caddr.in6;
    fl6.fl6_saddr = conn->vaddr.in6;
    rt6 = route6_output(mbuf, &fl6);
    if (!rt6) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    dp_vs_conn_cache_rt6(conn, rt6, false);

    mtu = rt6->rt6_mtu;
    if (mbuf->pkt_len > mtu) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu);
        err = EDPVS_FRAG;
        goto errout;
    }

    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;

    /* after route lookup and before translation */
    if (xmit_ttl) {
        if (unlikely(ip6h->ip6_hops <= 1)) {
            icmp6_send(mbuf, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
            err = EDPVS_DROP;
            goto errout;
        }

        ip6h->ip6_hops--;
    }

    /* L3 translation before l4 re-csum */
    ip6h->ip6_src = conn->vaddr.in6;

    /* L4 NAT translation */
    if (proto->fnat_in_handler) {
        err = proto->nat_out_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt6->rt6_dev, ip6_output);

errout:
    if (rt6)
        route6_put(rt6);
    rte_pktmbuf_free(mbuf);
    return err;
}

int dp_vs_out_xmit_nat(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn,
                       struct rte_mbuf *mbuf)
{
    int af = conn->af;

    assert(af == AF_INET || af == AF_INET6);

    return af == AF_INET ? __dp_vs_out_xmit_nat4(proto, conn, mbuf)
        : __dp_vs_out_xmit_nat6(proto, conn, mbuf);
}

/*
 * IP-IP tunnel is used for IPv4 IPVS tunnel forwarding.
 * `tunl0` should be configured up on RS.
 * */
static int __dp_vs_xmit_tunnel4(struct dp_vs_proto *proto,
                                struct dp_vs_conn *conn,
                                struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct rte_ipv4_hdr *new_iph, *old_iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    uint8_t tos = old_iph->type_of_service;
    uint16_t df = old_iph->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG);
    int err, mtu;
    uint32_t ip4h_len = sizeof(struct rte_ipv4_hdr);

    /*
     * drop old route. just for safe, because
     * TUNNEL is PREROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: TUNNEL have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
        route4_put(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr = conn->daddr.in;
    fl4.fl4_tos = tos;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    dp_vs_conn_cache_rt(conn, rt, true);

    mtu = rt->mtu;
    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    if (mbuf->pkt_len + ip4h_len > mtu && df) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                  htonl(mtu - ip4h_len));
        err = EDPVS_FRAG;
        goto errout;
    }

    new_iph = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend(mbuf, ip4h_len);
    if (!new_iph) {
        RTE_LOG(WARNING, IPVS, "%s: mbuf has not enough headroom"
                " space for ipvs tunnel\n", __func__);
        err = EDPVS_NOROOM;
        goto errout;
    }

    memset(new_iph, 0, ip4h_len);
    new_iph->version_ihl = 0x45;
    new_iph->type_of_service = tos;
    new_iph->total_length = htons(mbuf->pkt_len);
    new_iph->fragment_offset = df;
    new_iph->time_to_live = old_iph->time_to_live;
    new_iph->next_proto_id = IPPROTO_IPIP;
    new_iph->src_addr = rt->src.s_addr;
    new_iph->dst_addr=conn->daddr.in.s_addr;
    new_iph->packet_id = ip4_select_id(new_iph);

    if (rt->port && rt->port->flag & NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD) {
        mbuf->ol_flags |= PKT_TX_IP_CKSUM;
        new_iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(new_iph);
    }

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

/*
 * IPv6-IPv6 tunnel is used for IPv6 IPVS tunnel forwarding.
 * `ip6tnl0` should be configured up on RS.
 * */
static int __dp_vs_xmit_tunnel6(struct dp_vs_proto *proto,
                   struct dp_vs_conn *conn,
                   struct rte_mbuf *mbuf)
{
    struct flow6 fl6;
    struct ip6_hdr *new_ip6h, *old_ip6h = ip6_hdr(mbuf);
    struct route6 *rt6;
    int err, mtu;
    uint32_t ip6h_len = sizeof(struct ip6_hdr);

    /*
     * drop old route. just for safe, because
     * TUNNEL is PREROUTING, should not have route.
     */
    if (MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL) {
        RTE_LOG(WARNING, IPVS, "%s: TUNNEL have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
        route6_put(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
    }

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_daddr = conn->daddr.in6;
    rt6 = route6_output(mbuf, &fl6);
    if (!rt6) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    dp_vs_conn_cache_rt6(conn, rt6, true);

    mtu = rt6->rt6_mtu;
    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;

    if (mbuf->pkt_len + ip6h_len > mtu) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu - ip6h_len);
        err = EDPVS_FRAG;
        goto errout;
    }

    new_ip6h = (struct ip6_hdr*)rte_pktmbuf_prepend(mbuf, ip6h_len);
    if (!new_ip6h) {
        RTE_LOG(WARNING, IPVS, "%s: mbuf has not enough headroom"
                " space for ipvs tunnel\n", __func__);
        err = EDPVS_NOROOM;
        goto errout;
    }

    memset(new_ip6h, 0, ip6h_len);
    new_ip6h->ip6_flow = old_ip6h->ip6_flow;
    new_ip6h->ip6_plen = htons(mbuf->pkt_len - ip6h_len);
    new_ip6h->ip6_nxt = IPPROTO_IPV6;
    new_ip6h->ip6_hops = old_ip6h->ip6_hops;

    new_ip6h->ip6_src = rt6->rt6_src.addr.in6;
    if (unlikely(ipv6_addr_any(&new_ip6h->ip6_src))) {
        RTE_LOG(INFO, IPVS, "%s: route6 without source, slect source"
                " address from inetaddr.\n", __func__);
        inet_addr_select(AF_INET6, rt6->rt6_dev,
                (const union inet_addr*)&fl6.fl6_daddr, 0,
                (union inet_addr*)&new_ip6h->ip6_src);
    }

    new_ip6h->ip6_dst = conn->daddr.in6;

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt6->rt6_dev, ip6_output);

errout:
    if (rt6)
        route6_put(rt6);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int __dp_vs_xmit_tunnel_6o4(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    int err, mtu;
    struct flow4 fl4;
    struct route_entry *rt;
    struct rte_ipv4_hdr *new_iph;
    struct ip6_hdr *old_ip6h = ip6_hdr(mbuf);
    uint32_t ip4h_len = sizeof(struct rte_ipv4_hdr);

    /*
     * drop old route. just for safe, because
     * TUNNEL is PREROUTING, should not have route.
     */
    if (unlikely(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: TUNNEL have route %p ?\n", __func__,
                MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
        route6_put(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr = conn->daddr.in;
    fl4.fl4_tos = 0;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    dp_vs_conn_cache_rt(conn, rt, true);

    mtu = rt->mtu;
    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    if (mbuf->pkt_len + ip4h_len > mtu) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu - ip4h_len);
        err = EDPVS_FRAG;
        goto errout;
    }

    new_iph = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend(mbuf, ip4h_len);
    if (!new_iph) {
        RTE_LOG(WARNING, IPVS, "%s: mbuf has not enough headroom"
                " space for ipvs tunnel\n", __func__);
        err = EDPVS_NOROOM;
        goto errout;
    }

    memset(new_iph, 0, ip4h_len);
    new_iph->version_ihl = 0x45;
    new_iph->type_of_service = 0;
    new_iph->total_length = htons(mbuf->pkt_len);
    new_iph->fragment_offset = htons(RTE_IPV4_HDR_DF_FLAG);
    new_iph->time_to_live = old_ip6h->ip6_hlim;
    new_iph->next_proto_id = IPPROTO_IPV6;
    new_iph->src_addr = rt->src.s_addr;
    new_iph->dst_addr=conn->daddr.in.s_addr;
    new_iph->packet_id = ip4_select_id(new_iph);

    if (rt->port && rt->port->flag & NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD) {
        mbuf->ol_flags |= PKT_TX_IP_CKSUM;
        new_iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(new_iph);
    }

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

int dp_vs_xmit_tunnel(struct dp_vs_proto *proto,
                      struct dp_vs_conn *conn,
                      struct rte_mbuf *mbuf)
{
    int iaf = tuplehash_in(conn).af;
    int oaf = tuplehash_out(conn).af;

    assert(iaf == AF_INET || iaf == AF_INET6);
    assert(oaf == AF_INET || oaf == AF_INET6);

    /*
     * dp_vs_xmit_tunnel encapsulates packets directly rather than using tunnel device.
     * But on RealServers, corresponding tunnel device should be configured up. For Linux,
     * the following configs may be made:
     * 1. ifconfig tunl0/ip6tnl0/sit0 up for ip-ip/ip6-ip6/ip6-over-ip4 tunnel respectively
     * 2. add vip onto the configured tunnel device, then ignore arp for it
     * 3. set proper rp_filter mode for the tunnel device
     */

    /* ip-ip tunnel */
    if (AF_INET == iaf)
        return __dp_vs_xmit_tunnel4(proto, conn, mbuf);

    /* ip6-ip6 tunnel */
    if (AF_INET6 == oaf)
        return __dp_vs_xmit_tunnel6(proto, conn, mbuf);

    /* ip6-over-ip4 tunnel */
    return __dp_vs_xmit_tunnel_6o4(proto, conn, mbuf);
}

static void conn_fast_xmit_handler(vector_t tockens)
{
    RTE_LOG(INFO, IPVS, "fast xmit OFF\n");
    fast_xmit_close = true;
}

static void xmit_ttl_handler(vector_t tockens)
{
    RTE_LOG(INFO, IPVS, "enable xmit ttl\n");
    xmit_ttl = true;
}

void install_xmit_keywords(void)
{
    install_keyword("fast_xmit_close", conn_fast_xmit_handler, KW_TYPE_INIT);
    install_keyword("xmit_ttl", xmit_ttl_handler, KW_TYPE_NORMAL);
}
