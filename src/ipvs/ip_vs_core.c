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
#include <assert.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "conf/common.h"
#include "ipv4.h"
#include "ipv6.h"
#include "icmp.h"
#include "icmp6.h"
#include "sa_pool.h"
#include "ipvs/ipvs.h"
#include "ipvs/conn.h"
#include "ipvs/proto.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "ipvs/xmit.h"
#include "ipvs/synproxy.h"
#include "ipvs/blklst.h"
#include "ipvs/whtlst.h"
#include "ipvs/proto_udp.h"
#include "route6.h"
#include "ipvs/redirect.h"

static inline int dp_vs_fill_iphdr(int af, struct rte_mbuf *mbuf,
                                   struct dp_vs_iphdr *iph)
{
    if (af == AF_INET) {
        struct rte_ipv4_hdr *ip4h = ip4_hdr(mbuf);
        iph->af     = AF_INET;
        iph->len    = ip4_hdrlen(mbuf);
        iph->proto  = ip4h->next_proto_id;
        iph->saddr.in.s_addr = ip4h->src_addr;
        iph->daddr.in.s_addr = ip4h->dst_addr;
    } else if (af == AF_INET6) {
        struct ip6_hdr *ip6h = ip6_hdr(mbuf);
        uint8_t ip6nxt = ip6h->ip6_nxt;
        iph->af         = AF_INET6;
        iph->len        = ip6_skip_exthdr(mbuf, sizeof(struct ip6_hdr), &ip6nxt);
        iph->proto      = ip6nxt;
        iph->saddr.in6  = ip6h->ip6_src;
        iph->daddr.in6  = ip6h->ip6_dst;
    } else {
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

/*
 * IPVS persistent scheduling funciton.
 * It create a connection entry according to its template if exists,
 * or selects a server and creates a connection entry plus a template.
 */
static struct dp_vs_conn *dp_vs_sched_persist(struct dp_vs_service *svc,
        const struct dp_vs_iphdr *iph, struct rte_mbuf *mbuf, bool is_synproxy_on)
{
    uint32_t conn_flags;
    uint16_t _ports[2], *ports;
    uint16_t dport;
    struct dp_vs_dest *dest;
    struct dp_vs_conn *conn, *ct;
    struct dp_vs_conn_param param;
    union inet_addr snet;   /* source network of eth client after masking */
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char sbuf[64], dbuf[64], maskbuf[64];
#endif

    assert(svc && iph && mbuf);

    conn_flags = (is_synproxy_on ? DPVS_CONN_F_SYNPROXY : 0);
    if (svc->flags | DP_VS_SVC_F_EXPIRE_QUIESCENT)
        conn_flags |= DPVS_CONN_F_EXPIRE_QUIESCENT;

    if (svc->af == AF_INET6) {
        /* FIXME: Is OK to use svc->netmask as IPv6 prefix length ? */
        ipv6_addr_prefix_copy(&snet.in6, &iph->saddr.in6, svc->netmask);
    } else {
        snet.in.s_addr = iph->saddr.in.s_addr & svc->netmask;
    }

    ports = mbuf_header_pointer(mbuf, iph->len, sizeof(_ports), _ports);
    if (!ports)
        return NULL;

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS, "%s: persist-schedule: src %s/%u dest %s/%u snet %s\n",
            __func__,
            inet_ntop(svc->af, &iph->saddr, sbuf, sizeof(sbuf)),
            ntohs(ports[0]),
            inet_ntop(svc->af, &iph->daddr, dbuf, sizeof(dbuf)),
            ntohs(ports[1]),
            inet_ntop(svc->af, &snet, maskbuf, sizeof(maskbuf)));
#endif

    if (ports[1] == svc->port) {
        /* regular persistent service: <proto, caddr, 0, vaddr, vport, daddr, dport> */
        ct = dp_vs_ct_in_get(svc->af, iph->proto, &snet, &iph->daddr, 0, ports[1]);
        if (!ct || !dp_vs_check_template(ct)) {
            /* no template found, or the dest of the conn template is not available */
            dest = svc->scheduler->schedule(svc, mbuf, iph);
            if (unlikely(NULL == dest)) {
                RTE_LOG(WARNING, IPVS, "%s: persist-schedule: no dest found.\n", __func__);
                return NULL;
            }
            /* create a conn template */
            dp_vs_conn_fill_param(iph->af, iph->proto, &snet, &iph->daddr,
                    0, ports[1], 0, &param);

            ct = dp_vs_conn_new(mbuf, iph, &param, dest, conn_flags | DPVS_CONN_F_TEMPLATE);
            if(unlikely(NULL == ct))
                return NULL;

            ct->timeout.tv_sec = svc->timeout;
        } else {
            /* set destination with the found template */
            dest = ct->dest;
        }
        dport = dest->port;
    } else {
        /* port zero service: <proto, caddr, 0, vaddr, 0, daddr, 0>
         * fw-mark based service: not support */
        ct = dp_vs_ct_in_get(svc->af, iph->proto, &snet, &iph->daddr, 0, 0);
        if (!ct || !dp_vs_check_template(ct)) {
            dest = svc->scheduler->schedule(svc, mbuf, iph);
            if (unlikely(NULL == dest)) {
                RTE_LOG(WARNING, IPVS, "%s: persist-schedule: no dest found.\n", __func__);
                return NULL;
            }
            /* create a conn template */
            dp_vs_conn_fill_param(iph->af, iph->proto, &snet, &iph->daddr,
                    0, 0, 0, &param);

            ct = dp_vs_conn_new(mbuf, iph, &param, dest, conn_flags | DPVS_CONN_F_TEMPLATE);
            if(unlikely(NULL == ct))
                return NULL;

            ct->timeout.tv_sec = svc->timeout;
        } else {
            /* set destination with the found template */
            dest = ct->dest;
        }
        dport = ports[1];
    }

    /* create a new connection according to the template */
    dp_vs_conn_fill_param(iph->af, iph->proto, &iph->saddr, &iph->daddr,
            ports[0], ports[1], dport, &param);

    conn = dp_vs_conn_new(mbuf, iph, &param, dest, conn_flags);
    if (unlikely(NULL == conn)) {
        dp_vs_conn_put(ct);
        return NULL;
    }

    /* add control for the new connection */
    dp_vs_control_add(conn, ct);
    dp_vs_conn_put(ct);

    dp_vs_stats_conn(conn);

    return conn;
}

static struct dp_vs_conn *dp_vs_snat_schedule(struct dp_vs_dest *dest,
                                       const struct dp_vs_iphdr *iph,
                                       uint16_t *ports,
                                       struct rte_mbuf *mbuf)
{
    int err;
    struct dp_vs_conn *conn;
    struct dp_vs_conn_param param;
    struct sockaddr_storage daddr, saddr;
    uint16_t _ports[2];

    if (unlikely(iph->proto == IPPROTO_ICMP)) {
        struct icmphdr *ich, _icmph;
        ich = mbuf_header_pointer(mbuf, iph->len, sizeof(_icmph), &_icmph);
        if (!ich)
            return NULL;

        _ports[0] = icmp4_id(ich);
        _ports[1] = ich->type << 8 | ich->code;

        /* ID may confict for diff host,
         * need we use ID pool ? */
        dp_vs_conn_fill_param(iph->af, iph->proto,
                              &iph->daddr, &dest->addr,
                              _ports[1], _ports[0],
                              0, &param);
    } else if (unlikely(iph->proto == IPPROTO_ICMPV6)) {
        struct icmp6_hdr *ic6h, _ic6hp;
        ic6h = mbuf_header_pointer(mbuf, iph->len, sizeof(_ic6hp), &_ic6hp);
        if (!ic6h)
            return NULL;

        _ports[0] = icmp6h_id(ic6h);
        _ports[1] = ic6h->icmp6_type << 8 | ic6h->icmp6_code;

        dp_vs_conn_fill_param(iph->af, iph->proto,
                              &iph->daddr, &dest->addr,
                              _ports[1], _ports[0],
                              0, &param);
    } else {
        /* we cannot inherit dest (host's src port),
         * that may confict for diff hosts,
         * and using dest->port is worse choice. */
        if (iph->af == AF_INET) {
            struct sockaddr_in *daddr4 = (struct sockaddr_in *)&daddr;
            struct sockaddr_in *saddr4 = (struct sockaddr_in *)&saddr;

            memset(&daddr, 0, sizeof(daddr));
            daddr4->sin_family = AF_INET;
            daddr4->sin_addr = iph->daddr.in;
            daddr4->sin_port = ports[1];

            memset(&saddr, 0, sizeof(saddr));
            saddr4->sin_family = AF_INET;
            saddr4->sin_addr = dest->addr.in;
            saddr4->sin_port = 0;

            err = sa_fetch(AF_INET, NULL, &daddr, &saddr);
            if (err != 0)
                return NULL;
            dp_vs_conn_fill_param(AF_INET, iph->proto, &iph->daddr, &dest->addr,
                    ports[1], saddr4->sin_port, 0, &param);
        } else { /* AF_INET6 */
            struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)&daddr;
            struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)&saddr;

            memset(&daddr, 0, sizeof(daddr));
            daddr6->sin6_family = AF_INET6;
            daddr6->sin6_addr = iph->daddr.in6;
            daddr6->sin6_port = ports[1];

            memset(&saddr, 0, sizeof(saddr));
            saddr6->sin6_family = AF_INET6;
            saddr6->sin6_addr = dest->addr.in6;
            saddr6->sin6_port = 0;

            err = sa_fetch(AF_INET6, NULL, &daddr, &saddr);
            if (err != 0)
                return NULL;
            dp_vs_conn_fill_param(AF_INET6, iph->proto, &iph->daddr, &dest->addr,
                    ports[1], saddr6->sin6_port, 0, &param);
        }
    }
    conn = dp_vs_conn_new(mbuf, iph, &param, dest, 0);
    if (!conn) {
        sa_release(NULL, &daddr, &saddr);
        return NULL;
    }

    dp_vs_stats_conn(conn);
    return conn;
}

/* select an RS by service's scheduler and create a connection */
struct dp_vs_conn *dp_vs_schedule(struct dp_vs_service *svc,
                                  const struct dp_vs_iphdr *iph,
                                  struct rte_mbuf *mbuf,
                                  bool is_synproxy_on)
{
    uint16_t _ports[2], *ports; /* sport, dport */
    struct dp_vs_dest *dest;
    struct dp_vs_conn *conn;
    struct dp_vs_conn_param param;
    uint32_t flags = 0;

    assert(svc && iph && mbuf);

    ports = mbuf_header_pointer(mbuf, iph->len, sizeof(_ports), _ports);
    if (!ports)
        return NULL;

    /* persistent service */
    if (svc->flags & DP_VS_SVC_F_PERSISTENT)
        return dp_vs_sched_persist(svc, iph,  mbuf, is_synproxy_on);

    dest = svc->scheduler->schedule(svc, mbuf, iph);
    if (!dest) {
        RTE_LOG(INFO, IPVS, "%s: no dest found.\n", __func__);
#ifdef CONFIG_DPVS_MBUF_DEBUG
        dp_vs_mbuf_dump("found dest failed.", iph->af, mbuf);
#endif
        return NULL;
    }

    if (dest->fwdmode == DPVS_FWD_MODE_SNAT)
        return dp_vs_snat_schedule(dest, iph, ports, mbuf);

    if (unlikely(iph->proto == IPPROTO_ICMP)) {
        struct icmphdr *ich, _icmph;
        ich = mbuf_header_pointer(mbuf, iph->len, sizeof(_icmph), &_icmph);
        if (!ich)
            return NULL;

        ports = _ports;
        _ports[0] = icmp4_id(ich);
        _ports[1] = ich->type << 8 | ich->code;

        dp_vs_conn_fill_param(iph->af, iph->proto,
                              &iph->saddr, &iph->daddr,
                              ports[0], ports[1], 0, &param);
    } else if (unlikely(iph->proto == IPPROTO_ICMPV6)) {
        struct icmp6_hdr *ic6h, _ic6hp;
        ic6h = mbuf_header_pointer(mbuf, iph->len, sizeof(_ic6hp), &_ic6hp);
        if (!ic6h)
            return NULL;

        ports = _ports;
        _ports[0] = icmp6h_id(ic6h);
        _ports[1] = ic6h->icmp6_type << 8 | ic6h->icmp6_code;

        dp_vs_conn_fill_param(iph->af, iph->proto,
                              &iph->daddr, &dest->addr,
                              ports[1], ports[0],
                              0, &param);
    } else {
        dp_vs_conn_fill_param(iph->af, iph->proto,
                              &iph->saddr, &iph->daddr,
                              ports[0], ports[1], 0, &param);
    }

    if (is_synproxy_on)
        flags |= DPVS_CONN_F_SYNPROXY;
    if (svc->flags & DP_VS_SVC_F_ONEPACKET && iph->proto == IPPROTO_UDP)
        flags |= DPVS_CONN_F_ONE_PACKET;
    if (svc->flags & DP_VS_SVC_F_EXPIRE_QUIESCENT)
        flags |= DPVS_CONN_F_EXPIRE_QUIESCENT;

    conn = dp_vs_conn_new(mbuf, iph, &param, dest, flags);
    if (!conn)
        return NULL;

    dp_vs_stats_conn(conn);
    return conn;
}

/* return verdict INET_XXX */
static int xmit_outbound(struct rte_mbuf *mbuf,
                         struct dp_vs_proto *prot,
                         struct dp_vs_conn *conn)
{
    int err;
    assert(mbuf && prot && conn);

    if (dp_vs_stats_out(conn, mbuf)) {
        dp_vs_conn_put(conn);
        return INET_DROP;
    }

    if (!conn->packet_out_xmit) {
        RTE_LOG(WARNING, IPVS, "%s: missing out_xmit\n", __func__);
        dp_vs_conn_put(conn);
        return INET_ACCEPT;
    }

    err = conn->packet_out_xmit(prot, conn, mbuf);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to out xmit: %d\n", __func__, err);

    dp_vs_conn_put(conn);
    /* always stolen the packet */
    return INET_STOLEN;
}

/* return verdict INET_XXX */
static int xmit_inbound(struct rte_mbuf *mbuf,
                        struct dp_vs_proto *prot,
                        struct dp_vs_conn *conn)
{
    int err;
    assert(mbuf && prot && conn);

    if (dp_vs_stats_in(conn, mbuf)) {
        dp_vs_conn_put(conn);
        return INET_DROP;
    }

    /* is dest avaible to forward the packet ? */
    if (!conn->dest) {
        /* silently drop packet without reset connection timer.
         * wait for dest available or connection timeout. */
        dp_vs_conn_put_no_reset(conn);
        return INET_DROP;
    }

    if (!conn->packet_xmit) {
        RTE_LOG(WARNING, IPVS, "%s: missing packet_xmit\n", __func__);
        dp_vs_conn_put(conn);
        return INET_ACCEPT;
    }

    /* forward to RS */
    err = conn->packet_xmit(prot, conn, mbuf);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to transmit: %d\n", __func__, err);

    dp_vs_conn_put(conn);
    /* always stolen the packet */
    return INET_STOLEN;
}

/* mbuf should be consumed here. */
static int __xmit_outbound_icmp4(struct rte_mbuf *mbuf,
                                 struct dp_vs_proto *prot,
                                 struct dp_vs_conn *conn)
{
    struct flow4 fl4;
    struct route_entry *rt = NULL;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);

    /* no translation needed for DR/TUN. */
    if (conn->dest->fwdmode != DPVS_FWD_MODE_FNAT &&
        conn->dest->fwdmode != DPVS_FWD_MODE_NAT  &&
        conn->dest->fwdmode != DPVS_FWD_MODE_SNAT) {
        if (!conn->packet_out_xmit) {
            RTE_LOG(WARNING, IPVS, "%s: missing packet_out_xmit\n", __func__);
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOTSUPP;
        }

        return conn->packet_out_xmit(prot, conn, mbuf);
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr = conn->caddr.in;
    fl4.fl4_saddr = conn->vaddr.in;
    fl4.fl4_tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROUTE;
    }

    if ((mbuf->pkt_len > rt->mtu)
            && (ip4_hdr(mbuf)->fragment_offset & RTE_IPV4_HDR_DF_FLAG)) {
        route4_put(rt);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                  htonl(rt->mtu));
        rte_pktmbuf_free(mbuf);
        return EDPVS_FRAG;
    }

    if (unlikely(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) != NULL))
        route4_put(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    /* translation for outer L3, ICMP, and inner L3 and L4 */
    dp_vs_xmit_icmp(mbuf, prot, conn, DPVS_CONN_DIR_OUTBOUND);

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);
}

/* mbuf should be consumed here. */
static int __xmit_outbound_icmp6(struct rte_mbuf *mbuf,
                                 struct dp_vs_proto *prot,
                                 struct dp_vs_conn *conn)
{
    struct flow6 fl6;
    struct route6 *rt6 = NULL;

    /* no translation needed for DR/TUN. */
    if (conn->dest->fwdmode != DPVS_FWD_MODE_FNAT &&
        conn->dest->fwdmode != DPVS_FWD_MODE_NAT  &&
        conn->dest->fwdmode != DPVS_FWD_MODE_SNAT) {
        if (!conn->packet_out_xmit) {
            RTE_LOG(WARNING, IPVS, "%s: missing packet_out_xmit\n", __func__);
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOTSUPP;
        }

        return conn->packet_out_xmit(prot, conn, mbuf);
    }

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_daddr = conn->caddr.in6;
    fl6.fl6_saddr = conn->vaddr.in6;
    rt6 = route6_output(mbuf, &fl6);
    if (!rt6) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROUTE;
    }

    if (mbuf->pkt_len > rt6->rt6_mtu) {
        route6_put(rt6);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, rt6->rt6_mtu);
        rte_pktmbuf_free(mbuf);
        return EDPVS_FRAG;
    }

    if (unlikely(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL))
        route6_put(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;

    /* translation for outer L3, ICMP, and inner L3 and L4 */
    dp_vs_xmit_icmp(mbuf, prot, conn, DPVS_CONN_DIR_OUTBOUND);

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt6->rt6_dev, ip6_output);
}

static int xmit_outbound_icmp(struct rte_mbuf *mbuf,
                              struct dp_vs_proto *prot,
                              struct dp_vs_conn *conn)
{
    int af = conn->af;

    assert(af == AF_INET || af == AF_INET6);
    if (af == AF_INET)
        return __xmit_outbound_icmp4(mbuf, prot, conn);
    else
        return __xmit_outbound_icmp6(mbuf, prot, conn);
}

/* mbuf should be consumed here. */
static int __xmit_inbound_icmp4(struct rte_mbuf *mbuf,
                                  struct dp_vs_proto *prot,
                                  struct dp_vs_conn *conn)
{
    struct flow4 fl4;
    struct route_entry *rt = NULL;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);

    /* no translation needed for DR/TUN. */
    if (conn->dest->fwdmode != DPVS_FWD_MODE_NAT  &&
    conn->dest->fwdmode != DPVS_FWD_MODE_FNAT &&
    conn->dest->fwdmode != DPVS_FWD_MODE_SNAT) {
        if (!conn->packet_xmit) {
            RTE_LOG(WARNING, IPVS, "%s: missing packet_xmit\n", __func__);
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOTSUPP;
        }

        return conn->packet_xmit(prot, conn, mbuf);
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr = conn->daddr.in;
    fl4.fl4_saddr = conn->laddr.in;
    fl4.fl4_tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROUTE;
    }

    if ((mbuf->pkt_len > rt->mtu)
            && (ip4_hdr(mbuf)->fragment_offset & RTE_IPV4_HDR_DF_FLAG)) {
        route4_put(rt);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                  htonl(rt->mtu));
        rte_pktmbuf_free(mbuf);
        return EDPVS_FRAG;
    }

    if (unlikely(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) != NULL))
        route4_put(MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE));
    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    /* translation for outer L3, ICMP, and inner L3 and L4 */
    dp_vs_xmit_icmp(mbuf, prot, conn, DPVS_CONN_DIR_INBOUND);

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);
}


/* mbuf should be consumed here. */
static int __xmit_inbound_icmp6(struct rte_mbuf *mbuf,
                                struct dp_vs_proto *prot,
                                struct dp_vs_conn *conn)
{
    struct flow6 fl6;
    struct route6 *rt6 = NULL;

    /* no translation needed for DR/TUN. */
    if (conn->dest->fwdmode != DPVS_FWD_MODE_NAT  &&
        conn->dest->fwdmode != DPVS_FWD_MODE_FNAT &&
        conn->dest->fwdmode != DPVS_FWD_MODE_SNAT) {
        if (!conn->packet_xmit) {
            RTE_LOG(WARNING, IPVS, "%s: missing packet_xmit\n", __func__);
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOTSUPP;
        }

        return conn->packet_xmit(prot, conn, mbuf);
    }

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_daddr = conn->daddr.in6;
    fl6.fl6_saddr = conn->laddr.in6;
    rt6 = route6_output(mbuf, &fl6);
    if (!rt6) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROUTE;
    }

    if (mbuf->pkt_len > rt6->rt6_mtu) {
        route6_put(rt6);
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, rt6->rt6_mtu);
        rte_pktmbuf_free(mbuf);
        return EDPVS_FRAG;
    }

    if (unlikely(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) != NULL))
        route6_put(MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE));
    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;

    /* translation for outer L3, ICMP, and inner L3 and L4 */
    dp_vs_xmit_icmp(mbuf, prot, conn, DPVS_CONN_DIR_INBOUND);

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt6->rt6_dev, ip6_output);
}

static int xmit_inbound_icmp(struct rte_mbuf *mbuf,
                             struct dp_vs_proto *prot,
                             struct dp_vs_conn *conn)
{
    int af = conn->af;

    assert(af == AF_INET || af == AF_INET6);

    if (af == AF_INET)
        return __xmit_inbound_icmp4(mbuf, prot, conn);
    else
        return __xmit_inbound_icmp6(mbuf, prot, conn);
}

/* return verdict INET_XXX */
static int __dp_vs_in_icmp4(struct rte_mbuf *mbuf, int *related)
{
    struct icmphdr *ich, _icmph;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct rte_ipv4_hdr *ciph, _ciph;
    struct dp_vs_iphdr dciph;
    struct dp_vs_proto *prot;
    struct dp_vs_conn *conn;
    int off, dir, err;
    lcoreid_t cid, peer_cid;
    bool drop = false;

    *related = 0; /* not related until found matching conn */
    cid = peer_cid = rte_lcore_id();

    if (unlikely(ip4_is_frag(iph))) {
        if (ip4_defrag(mbuf, IP_DEFRAG_VS_FWD) != EDPVS_OK)
            return INET_STOLEN;
        iph = ip4_hdr(mbuf); /* reload with new mbuf */
        ip4_send_csum(iph);
    }

    off = ip4_hdrlen(mbuf);
    ich = mbuf_header_pointer(mbuf, off, sizeof(_icmph), &_icmph);
    if (unlikely(!ich))
        return INET_DROP;

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS, "ICMP (%d,%d) %08X->%08X\n",
            ich->type, ntohs(icmp4_id(ich)), iph->src_addr, iph->dst_addr);
#endif

    /* support these related error types only,
     * others either not support or not related. */
    if (ich->type != ICMP_DEST_UNREACH
            && ich->type != ICMP_SOURCE_QUENCH
            && ich->type != ICMP_TIME_EXCEEDED)
        return INET_ACCEPT;

    /* inner (contained) IP header */
    off += sizeof(struct icmphdr);
    ciph = mbuf_header_pointer(mbuf, off, sizeof(_ciph), &_ciph);
    if (unlikely(!ciph))
        return INET_ACCEPT;

    prot = dp_vs_proto_lookup(ciph->next_proto_id);
    if (!prot)
        return INET_ACCEPT;

    if (unlikely((ciph->fragment_offset & htons(RTE_IPV4_HDR_OFFSET_MASK)))) {
        RTE_LOG(WARNING, IPVS, "%s: frag needed.\n", __func__);
        return INET_DROP;
    }

    /*
     * lookup conn with inner IP pkt.
     * it need to move mbuf.data_off to inner IP pkt,
     * and restore it later. although it looks strange.
     */
    rte_pktmbuf_adj(mbuf, off);
    if (mbuf_may_pull(mbuf, sizeof(struct rte_ipv4_hdr)) != 0)
        return INET_DROP;
    dp_vs_fill_iphdr(AF_INET, mbuf, &dciph);

    conn = prot->conn_lookup(prot, &dciph, mbuf, &dir, true, &drop, &peer_cid);

    /*
     * The connection is not locally found, however the redirect is found so
     * forward the packet to the remote redirect owner core.
     */
    if (cid != peer_cid) {
        /* recover mbuf.data_off to outer Ether header */
        rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr) + off);

        return dp_vs_redirect_pkt(mbuf, peer_cid);
    }

    /* recover mbuf.data_off to outer IP header. */
    rte_pktmbuf_prepend(mbuf, off);

    if (!conn)
        return INET_ACCEPT;

    /* so the ICMP is related to existing conn */
    *related = 1;

    if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0) {
        RTE_LOG(WARNING, IPVS, "%s: may_pull icmp error\n", __func__);
        dp_vs_conn_put_no_reset(conn);
        return INET_DROP;
    }

    // re-fetch IP header and Icmp address
    iph = ip4_hdr(mbuf);
    ich = (struct icmphdr*)((void*)iph + ip4_hdrlen(mbuf));
    if (rte_raw_cksum(ich, mbuf->pkt_len - ip4_hdrlen(mbuf)) != 0xffff) {
        RTE_LOG(DEBUG, IPVS, "%s: bad checksum\n", __func__);
        dp_vs_conn_put_no_reset(conn);
        return INET_DROP;
    }

    if (dp_vs_stats_in(conn, mbuf)) {
        dp_vs_conn_put(conn);
        return INET_DROP;
    }
    /* note
     * 1. the direction of inner IP pkt is reversed with ICMP pkt.
     * 2. but we use (@reverse == true) for prot->conn_lookup()
     * as a result, @dir is same with icmp packet. */
    if (dir == DPVS_CONN_DIR_INBOUND)
        err = xmit_inbound_icmp(mbuf, prot, conn);
    else
        err = xmit_outbound_icmp(mbuf, prot, conn);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IPVS, "%s: xmit icmp error: %s\n",
                __func__, dpvs_strerror(err));

    dp_vs_conn_put_no_reset(conn);
    return INET_STOLEN;
}

#ifdef CONFIG_DPVS_IPVS_DEBUG
static void __dp_vs_icmp6_show(struct ip6_hdr *ip6h, struct icmp6_hdr *ic6h)
{
    char src_addr_buff[64], dst_addr_buff[64];

    inet_ntop(AF_INET6, &ip6h->ip6_src, src_addr_buff, sizeof(src_addr_buff));
    inet_ntop(AF_INET6, &ip6h->ip6_dst, dst_addr_buff, sizeof(dst_addr_buff));

    RTE_LOG(DEBUG, IPVS, "%s: ICMP6 (%d, %d) %s->%s\n",
            __func__, ic6h->icmp6_type, ntohs(icmp6h_id(ic6h)), src_addr_buff, dst_addr_buff);
}
#endif

/* return verdict INET_XXX */
static int __dp_vs_in_icmp6(struct rte_mbuf *mbuf, int *related)
{
    struct icmp6_hdr *ic6h, _icmp6h;
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    struct ip6_hdr *cip6h, _cip6h;
    struct dp_vs_iphdr dcip6h;
    struct dp_vs_proto *prot;
    struct dp_vs_conn *conn;
    int off, ic6h_off, dir, err;
    lcoreid_t cid, peer_cid;
    bool drop = false;
    uint8_t nexthdr = ip6h->ip6_nxt;

    *related = 0; /* not related until found matching conn */
    cid = peer_cid = rte_lcore_id();

    // don't suppurt frag now
    if (unlikely(ip6_is_frag(ip6h))) {
        RTE_LOG(WARNING, IPVS, "%s: ip packet is frag.\n", __func__);
        return INET_DROP;
    }

    off = sizeof(struct ip6_hdr);
    off = ip6_skip_exthdr(mbuf, off, &nexthdr);
    if (off < 0 || nexthdr != IPPROTO_ICMPV6) {
        RTE_LOG(WARNING, IPVS, "%s: off or nexthdr is illegal. off is %d, nexthdr is %u.\n",
                __func__, off, nexthdr);
        return INET_DROP;
    }

    ic6h_off = off;
    ic6h = mbuf_header_pointer(mbuf, off, sizeof(_icmp6h), &_icmp6h);
    if (unlikely(!ic6h))
        return INET_DROP;

#ifdef CONFIG_DPVS_IPVS_DEBUG
    __dp_vs_icmp6_show(ip6h, ic6h);
#endif

    /* support these related error types only,
     * others either not support or not related.
     */
    if (ic6h->icmp6_type != ICMP6_DST_UNREACH
            && ic6h->icmp6_type != ICMP6_PACKET_TOO_BIG
            && ic6h->icmp6_type != ICMP6_TIME_EXCEEDED)
        return INET_ACCEPT;

    /* inner (contained) IP header */
    off += sizeof(struct icmp6_hdr);
    cip6h = mbuf_header_pointer(mbuf, off, sizeof(_cip6h), &_cip6h);
    if (unlikely(!cip6h))
        return INET_ACCEPT;

    if (unlikely(ip6_is_frag(cip6h))) {
        RTE_LOG(WARNING, IPVS, "%s: frag needed.\n", __func__);
        return INET_ACCEPT;
    }

    /*
     * lookup conn with inner IP pkt.
     * it need to move mbuf.data_off to inner IP pkt,
     * and restore it later. although it looks strange.
     */
    rte_pktmbuf_adj(mbuf, off);
    if (mbuf_may_pull(mbuf, sizeof(struct ip6_hdr)) != 0)
        return INET_DROP;
    dp_vs_fill_iphdr(AF_INET6, mbuf, &dcip6h);

    prot = dp_vs_proto_lookup(dcip6h.proto);
    if (!prot)
        return INET_ACCEPT;

    conn = prot->conn_lookup(prot, &dcip6h, mbuf, &dir, true, &drop, &peer_cid);

    /*
     * The connection is not locally found, however the redirect is found so
     * forward the packet to the remote redirect owner core.
     */
    if (cid != peer_cid) {
        /* recover mbuf.data_off to outer Ether header */
        rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr) + off);

        return dp_vs_redirect_pkt(mbuf, peer_cid);
    }

    /* recover mbuf.data_off to outer IP header. */
    rte_pktmbuf_prepend(mbuf, off);

    if (!conn)
        return INET_ACCEPT;

    /* so the ICMP is related to existing conn */
    *related = 1;

    if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0) {
        RTE_LOG(WARNING, IPVS, "%s: may_pull icmp error\n", __func__);
        dp_vs_conn_put_no_reset(conn);
        return INET_DROP;
    }

    /*
     * check checksum
     * re-fetch IP header and Icmp address
     */
    ip6h = ip6_hdr(mbuf);
    ic6h = (struct icmp6_hdr *)((void*)(ip6h) + ic6h_off);
    if (icmp6_csum(ip6h, ic6h) != 0xffff) {
        RTE_LOG(DEBUG, IPVS, "%s: bad checksum\n", __func__);
        dp_vs_conn_put_no_reset(conn);
        return INET_DROP;
    }

    if (dp_vs_stats_in(conn, mbuf)) {
        dp_vs_conn_put(conn);
        return INET_DROP;
    }
    /* note
     * 1. the direction of inner IP pkt is reversed with ICMP pkt.
     * 2. but we use (@reverse == true) for prot->conn_lookup()
     * as a result, @dir is same with icmp packet. */
    if (dir == DPVS_CONN_DIR_INBOUND)
        err = xmit_inbound_icmp(mbuf, prot, conn);
    else
        err = xmit_outbound_icmp(mbuf, prot, conn);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IPVS, "%s: xmit icmp error: %s\n",
                __func__, dpvs_strerror(err));

    dp_vs_conn_put_no_reset(conn);
    return INET_STOLEN;
}

static int dp_vs_in_icmp(int af, struct rte_mbuf *mbuf, int *related)
{
    *related = 0;
    switch (af) {
    case AF_INET:
        return __dp_vs_in_icmp4(mbuf, related);
    case AF_INET6:
        return __dp_vs_in_icmp6(mbuf, related);
    }
    return INET_ACCEPT;
}

/* return verdict INET_XXX
 * af from mbuf->l3_type? No! The field is rewritten by netif and conflicts with
 * m.packet_type(an union), so using a wrapper to get af.
 * */
static int __dp_vs_in(void *priv, struct rte_mbuf *mbuf,
                      const struct inet_hook_state *state, int af)
{
    struct dp_vs_iphdr iph;
    struct dp_vs_proto *prot;
    struct dp_vs_conn *conn;
    int dir, verdict, err, related;
    bool drop = false;
    lcoreid_t cid, peer_cid;
    eth_type_t etype = mbuf->packet_type; /* FIXME: use other field ? */
    assert(mbuf && state);

    cid = peer_cid = rte_lcore_id();

    if (unlikely(etype != ETH_PKT_HOST))
        return INET_ACCEPT;

    if (dp_vs_fill_iphdr(af, mbuf, &iph) != EDPVS_OK)
        return INET_ACCEPT;

    if (unlikely(iph.proto == IPPROTO_ICMP ||
                 iph.proto == IPPROTO_ICMPV6)) {
        /* handle related ICMP error to existing conn */
        verdict = dp_vs_in_icmp(af, mbuf, &related);
        if (related || verdict != INET_ACCEPT)
            return verdict;
        /* let unrelated and valid ICMP goes down,
         * may implement ICMP fwd in the futher. */
    }

    prot = dp_vs_proto_lookup(iph.proto);
    if (unlikely(!prot))
        return INET_ACCEPT;

    /*
     * Defrag ipvs-forwarding TCP/UDP is not supported for some reasons,
     *
     * - RSS/flow-director do not support TCP/UDP fragments, means it's
     *   not able to direct frags to same lcore as original TCP/UDP packets.
     * - per-lcore conn table will miss if frags reachs wrong lcore.
     *
     * If we redirect frags to "correct" lcore, it may cause performance
     * issue. Also it need to understand RSS algorithm. Moreover, for the
     * case frags in same flow are not occur in same lcore, a global lock is
     * needed, which is not a good idea.
     */
    if (af == AF_INET && ip4_is_frag(ip4_hdr(mbuf))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag not support.\n", __func__);
        return INET_DROP;
    }

    /* packet belongs to existing connection ? */
    conn = prot->conn_lookup(prot, &iph, mbuf, &dir, false, &drop, &peer_cid);
    if (unlikely(drop)) {
        RTE_LOG(DEBUG, IPVS, "%s: packet dropped by ipvs acl\n", __func__);
        return INET_DROP;
    }

    /*
     * The connection is not locally found, however the redirect is found so
     * forward the packet to the remote redirect owner core.
     */
    if (cid != peer_cid) {
        /* recover mbuf.data_off to outer Ether header */
        rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));

        return dp_vs_redirect_pkt(mbuf, peer_cid);
    }

    if (unlikely(!conn)) {
        /* try schedule RS and create new connection */
        if (prot->conn_sched(prot, &iph, mbuf, &conn, &verdict) != EDPVS_OK) {
            /* RTE_LOG(DEBUG, IPVS, "%s: fail to schedule.\n", __func__); */
            return verdict;
        }

        /* only SNAT triggers connection by inside-outside traffic. */
        if (conn->dest->fwdmode == DPVS_FWD_MODE_SNAT)
            dir = DPVS_CONN_DIR_OUTBOUND;
        else
            dir = DPVS_CONN_DIR_INBOUND;
    } else {
        /* assert(conn->dest != NULL); */
        if (prot->conn_expire_quiescent && (conn->flags & DPVS_CONN_F_EXPIRE_QUIESCENT) &&
                conn->dest && (!dp_vs_dest_is_avail(conn->dest) ||
                    rte_atomic16_read(&conn->dest->weight) == 0)) {
            RTE_LOG(INFO, IPVS, "%s: the conn is quiescent, expire it right now,"
                    " and drop the packet!\n", __func__);
            prot->conn_expire_quiescent(conn);
            dp_vs_conn_put(conn);
            return INET_DROP;
        }
    }

    if (conn->flags & DPVS_CONN_F_SYNPROXY) {
        if (dir == DPVS_CONN_DIR_INBOUND) {
            /* Filter out-in ack packet when cp is at SYN_SENT state.
             * Drop it if not a valid packet, store it otherwise */
            if (0 == dp_vs_synproxy_filter_ack(mbuf, conn, prot,
                                               &iph, &verdict)) {
                dp_vs_stats_in(conn, mbuf);
                dp_vs_conn_put(conn);
                return verdict;
            }

            /* "Reuse" synproxy sessions.
             * "Reuse" means update syn_proxy_seq struct
             * and clean ack_mbuf etc. */
            if (0 != dp_vs_synproxy_ctrl_conn_reuse) {
                if (0 == dp_vs_synproxy_reuse_conn(af, mbuf, conn, prot,
                                                   &iph, &verdict)) {
                    dp_vs_stats_in(conn, mbuf);
                    dp_vs_conn_put(conn);
                    return verdict;
                }
            }
        } else {
            /* Syn-proxy 3 logic: receive syn-ack from rs */
            if (dp_vs_synproxy_synack_rcv(mbuf, conn, prot,
                                          iph.len, &verdict) == 0) {
                dp_vs_stats_out(conn, mbuf);
                dp_vs_conn_put(conn);
                return verdict;
            }
        }
    }

    if (prot->state_trans) {
        err = prot->state_trans(prot, conn, mbuf, dir);
        if (err != EDPVS_OK)
            RTE_LOG(WARNING, IPVS, "%s: fail to trans state.", __func__);
    }
    conn->old_state = conn->state;

    /* holding the conn, need a "put" later. */
    if (dir == DPVS_CONN_DIR_INBOUND)
        return xmit_inbound(mbuf, prot, conn);
    else
        return xmit_outbound(mbuf, prot, conn);
}

static int dp_vs_in(void *priv, struct rte_mbuf *mbuf,
                      const struct inet_hook_state *state)
{
    return __dp_vs_in(priv, mbuf, state, AF_INET);
}

static int dp_vs_in6(void *priv, struct rte_mbuf *mbuf,
                      const struct inet_hook_state *state)
{
    return __dp_vs_in(priv, mbuf, state, AF_INET6);
}

static int __dp_vs_pre_routing(void *priv, struct rte_mbuf *mbuf,
                    const struct inet_hook_state *state, int af)
{
    struct dp_vs_iphdr iph;
    struct dp_vs_service *svc;

    if (EDPVS_OK != dp_vs_fill_iphdr(af, mbuf, &iph))
        return INET_ACCEPT;

    /* Drop all ip fragment except ospf */
    if ((af == AF_INET) && ip4_is_frag(ip4_hdr(mbuf))) {
        dp_vs_estats_inc(DEFENCE_IP_FRAG_DROP);
        return INET_DROP;
    }

    /* Drop udp packet which send to tcp-vip */
    if (g_defence_udp_drop && IPPROTO_UDP == iph.proto) {
        if ((svc = dp_vs_vip_lookup(af, IPPROTO_UDP, &iph.daddr, rte_lcore_id())) == NULL) {
            if ((svc = dp_vs_vip_lookup(af, IPPROTO_TCP, &iph.daddr, rte_lcore_id())) != NULL) {
                dp_vs_estats_inc(DEFENCE_UDP_DROP);
                return INET_DROP;
            }
        }
    }

    /* Synproxy: defence synflood */
    if (IPPROTO_TCP == iph.proto) {
        int v = INET_ACCEPT;
        if (0 == dp_vs_synproxy_syn_rcv(af, mbuf, &iph, &v))
            return v;
    }

    return INET_ACCEPT;
}

static int dp_vs_pre_routing(void *priv, struct rte_mbuf *mbuf,
                    const struct inet_hook_state *state)
{
    return __dp_vs_pre_routing(priv, mbuf, state, AF_INET);
}

static int dp_vs_pre_routing6(void *priv, struct rte_mbuf *mbuf,
                    const struct inet_hook_state *state)
{
    return __dp_vs_pre_routing(priv, mbuf, state, AF_INET6);
}

static struct inet_hook_ops dp_vs_ops[] = {
    {
        .af         = AF_INET,
        .hook       = dp_vs_in,
        .hooknum    = INET_HOOK_PRE_ROUTING,
        .priority   = 100,
    },
    {
        .af         = AF_INET,
        .hook       = dp_vs_pre_routing,
        .hooknum    = INET_HOOK_PRE_ROUTING,
        .priority   = 99,
    },
    {
        .af         = AF_INET6,
        .hook       = dp_vs_in6,
        .hooknum    = INET_HOOK_PRE_ROUTING,
        .priority   = 100,
    },
    {
        .af         = AF_INET6,
        .hook       = dp_vs_pre_routing6,
        .hooknum    = INET_HOOK_PRE_ROUTING,
        .priority   = 99,
    },
};

int dp_vs_init(void)
{
    int err;

    err = dp_vs_proto_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init proto: %s\n", dpvs_strerror(err));
        return err;
    }

    err = dp_vs_laddr_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init laddr: %s\n", dpvs_strerror(err));
        goto err_laddr;
    }

    err = dp_vs_conn_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init conn: %s\n", dpvs_strerror(err));
        goto err_conn;
    }

    err = dp_vs_redirects_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init redirect: %s\n", dpvs_strerror(err));
        goto err_redirect;
    }

    err = dp_vs_synproxy_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init synproxy: %s\n", dpvs_strerror(err));
        goto err_synproxy;
    }

    err = dp_vs_sched_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init sched: %s\n", dpvs_strerror(err));
        goto err_sched;
    }

    err = dp_vs_service_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init serv: %s\n", dpvs_strerror(err));
        goto err_serv;
    }

    err = dp_vs_blklst_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init blklst: %s\n", dpvs_strerror(err));
        goto err_blklst;
    }

    err = dp_vs_whtlst_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init whtlst: %s\n", dpvs_strerror(err));
        goto err_whtlst;
    }

    err = dp_vs_stats_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init stats: %s\n", dpvs_strerror(err));
        goto err_stats;
    }

    err = inet_register_hooks(dp_vs_ops, NELEMS(dp_vs_ops));
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to register hooks: %s\n", dpvs_strerror(err));
        goto err_hooks;
    }

    RTE_LOG(DEBUG, IPVS, "ipvs inialized.\n");
    return EDPVS_OK;

err_hooks:
    dp_vs_stats_term();
err_stats:
    dp_vs_whtlst_term();
err_whtlst:
    dp_vs_blklst_term();
err_blklst:
    dp_vs_service_term();
err_serv:
    dp_vs_sched_term();
err_sched:
    dp_vs_synproxy_term();
err_synproxy:
    dp_vs_redirects_term();
err_redirect:
    dp_vs_conn_term();
err_conn:
    dp_vs_laddr_term();
err_laddr:
    dp_vs_proto_term();

    return err;
}

int dp_vs_term(void)
{
    int err;

    err = inet_unregister_hooks(dp_vs_ops, NELEMS(dp_vs_ops));
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to unregister hooks: %s\n", dpvs_strerror(err));

    err = dp_vs_stats_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate term: %s\n", dpvs_strerror(err));

    err = dp_vs_whtlst_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate whtlst: %s\n", dpvs_strerror(err));

    err = dp_vs_blklst_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate blklst: %s\n", dpvs_strerror(err));

    err = dp_vs_service_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate serv: %s\n", dpvs_strerror(err));

    err = dp_vs_sched_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate sched: %s\n", dpvs_strerror(err));

    err = dp_vs_synproxy_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate synproxy: %s\n", dpvs_strerror(err));

    err = dp_vs_redirects_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate redirect: %s\n", dpvs_strerror(err));

    err = dp_vs_conn_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate conn: %s\n", dpvs_strerror(err));

    err = dp_vs_laddr_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate laddr: %s\n", dpvs_strerror(err));

    err = dp_vs_proto_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate proto: %s\n", dpvs_strerror(err));

    RTE_LOG(ERR, IPVS, "ipvs terminated.\n");
    return err;
}
