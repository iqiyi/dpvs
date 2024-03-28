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
/**
 * "match" classifier for traffic control module.
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "sctp/sctp.h"
#include "netif.h"
#include "vlan.h"
#include "tc/tc.h"
#include "tc/sch.h"
#include "tc/cls.h"
#include "linux_ipv6.h"
#include "ipv6.h"
#include "conf/match.h"
#include "conf/tc.h"

struct match_cls_priv {
    struct tc_cls           *cls;

    uint8_t                 proto;      /* IPPROTO_XXX */
    struct dp_vs_match      match;

    struct tc_cls_result    result;
};

static int match_classify(struct tc_cls *cls, struct rte_mbuf *mbuf,
                          struct tc_cls_result *result)
{
    struct match_cls_priv *priv = tc_cls_priv(cls);
    struct dp_vs_match *m = &priv->match;
    struct rte_ether_hdr *eh = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct iphdr *iph = NULL;
    struct ip6_hdr *ip6h = NULL;
    struct tcphdr *th;
    struct udphdr *uh;
    struct sctphdr *sh;
    uint8_t l4_proto = 0;
    int offset = sizeof(*eh);
    __be16 pkt_type = eh->ether_type;
    __be16 sport, dport;
    struct netif_port *idev, *odev;
    struct vlan_ethhdr *veh;
    int err = TC_ACT_RECLASSIFY; /* by default */

    idev = netif_port_get_by_name(m->iifname);
    odev = netif_port_get_by_name(m->oifname);
    sport = dport = 0;

    /* check input device for ingress */
    if (idev && (cls->sch->flags & QSCH_F_INGRESS)) {
        if (idev->id != mbuf->port)
            goto done;
    }

    /* check output device for egress */
    if (odev && !(cls->sch->flags & QSCH_F_INGRESS)) {
        if (odev->id != mbuf->port)
            goto done;
    }

    /* support IPv4 and 802.1q/IPv4 */
l2parse:
    switch (ntohs(pkt_type)) {
    case ETH_P_IP:
        if (m->af != AF_INET && m->af != AF_UNSPEC)
            goto done;

        if (mbuf_may_pull(mbuf, offset + sizeof(struct iphdr)) != 0) {
            err = TC_ACT_SHOT;
            goto done;
        }

        iph = rte_pktmbuf_mtod_offset(mbuf, struct iphdr *, offset);

        /* check if source/dest IP in range */
        if (m->srange.max_addr.in.s_addr != htonl(INADDR_ANY)) {
            if (ntohl(iph->saddr) < ntohl(m->srange.min_addr.in.s_addr) ||
                ntohl(iph->saddr) > ntohl(m->srange.max_addr.in.s_addr))
                goto done;
        }

        if (m->drange.max_addr.in.s_addr != htonl(INADDR_ANY)) {
            if (ntohl(iph->daddr) < ntohl(m->drange.min_addr.in.s_addr) ||
                ntohl(iph->daddr) > ntohl(m->drange.max_addr.in.s_addr))
                goto done;
        }

        l4_proto = iph->protocol;
        offset += (iph->ihl << 2);
        break;

    case ETH_P_IPV6:
        if (m->af != AF_INET6 && m->af != AF_UNSPEC)
            goto done;
        if (mbuf_may_pull(mbuf, offset + sizeof(struct ip6_hdr)) != 0) {
            err = TC_ACT_SHOT;
            goto done;
        }

        ip6h = rte_pktmbuf_mtod_offset(mbuf, struct ip6_hdr *, offset);
        if (!ipv6_addr_any(&m->srange.max_addr.in6)) {
            if (ipv6_addr_cmp(&ip6h->ip6_src, &m->srange.min_addr.in6) < 0 ||
                    ipv6_addr_cmp(&ip6h->ip6_src, &m->srange.max_addr.in6) > 0)
                goto done;
        }

        if (!ipv6_addr_any(&m->drange.max_addr.in6)) {
            if (ipv6_addr_cmp(&ip6h->ip6_dst, &m->drange.min_addr.in6) < 0 ||
                    ipv6_addr_cmp(&ip6h->ip6_dst, &m->drange.max_addr.in6) > 0)
                goto done;
        }

        l4_proto = ip6h->ip6_nxt;
        offset = ip6_skip_exthdr(mbuf, offset + sizeof(struct ip6_hdr), &l4_proto);
        if (offset < 0) {
            err = TC_ACT_SHOT;
            goto done;
        }
        break;

    case ETH_P_8021Q:
        veh = (struct vlan_ethhdr *)eh;
        pkt_type = veh->h_vlan_encapsulated_proto;
        offset += VLAN_HLEN;
        goto l2parse;

    default:
        goto done;
    }

    /* check if protocol matches */
    if (priv->proto && l4_proto && priv->proto != l4_proto)
        goto done;

    switch (l4_proto) {
    case IPPROTO_TCP:
        if (mbuf_may_pull(mbuf, offset + sizeof(struct tcphdr)) != 0) {
            err = TC_ACT_SHOT;
            goto done;
        }

        th = rte_pktmbuf_mtod_offset(mbuf, struct tcphdr *, offset);
        sport = th->source;
        dport = th->dest;
        break;

    case IPPROTO_UDP:
        if (mbuf_may_pull(mbuf, offset + sizeof(struct udphdr)) != 0) {
            err = TC_ACT_SHOT;
            goto done;
        }

        uh = rte_pktmbuf_mtod_offset(mbuf, struct udphdr *, offset);
        sport = uh->source;
        dport = uh->dest;
        break;

    case IPPROTO_SCTP:
        if (mbuf_may_pull(mbuf, offset + sizeof(struct sctphdr)) != 0) {
            err = TC_ACT_SHOT;
            goto done;
        }

        sh = rte_pktmbuf_mtod_offset(mbuf, struct sctphdr *, offset);
        sport = sh->src_port;
        dport = sh->dest_port;
        break;

    default: /* priv->proto is not assigned */
        goto match;
    }

    /* check if source/dest port in range */
    if (m->srange.max_port) {
        if (ntohs(sport) < ntohs(m->srange.min_port) ||
            ntohs(sport) > ntohs(m->srange.max_port))
            goto done;
    }

    if (m->drange.max_port) {
        if (ntohs(dport) < ntohs(m->drange.min_port) ||
            ntohs(dport) > ntohs(m->drange.max_port))
            goto done;
    }

match:
    /* all matchs */
    *result = priv->result;
    err = TC_ACT_OK;

done:
#if defined(CONFIG_TC_DEBUG)
    if (iph || ip6h) {
        char sip[64], dip[64];
        char cls_id[16], qsch_id[16];

        if (ip6h) {
            inet_ntop(AF_INET6, &ip6h->ip6_src, sip, sizeof(sip));
            inet_ntop(AF_INET6, &ip6h->ip6_dst, dip, sizeof(dip));
        } else {
            inet_ntop(AF_INET, &iph->saddr, sip, sizeof(sip));
            inet_ntop(AF_INET, &iph->daddr, dip, sizeof(dip));
        }
        tc_handle_itoa(cls->handle, cls_id, sizeof(cls_id));
        tc_handle_itoa(priv->result.sch_id, qsch_id, sizeof(qsch_id));

        RTE_LOG(DEBUG, TC, "cls %s %s %s:%u -> %s:%u %s %s\n",
                cls_id, inet_proto_name(l4_proto),
                sip, sport, dip, dport,
                (err == TC_ACT_OK ? "target" : "miss"),
                (err == TC_ACT_OK ? \
                    (priv->result.drop ? "drop" : qsch_id) : ""));
    }
#endif

    return err;
}

static int match_init(struct tc_cls *cls, const void *arg)
{
    struct match_cls_priv *priv = tc_cls_priv(cls);
    const struct tc_cls_match_copt *copt = arg;

    if (!arg)
        return EDPVS_INVAL;

    if (copt->proto)
        priv->proto = copt->proto;

    if (copt->match.af)
        priv->match.af = copt->match.af;

    if (strlen(copt->match.iifname))
        snprintf(priv->match.iifname, IFNAMSIZ, "%s", copt->match.iifname);

    if (strlen(copt->match.oifname))
        snprintf(priv->match.oifname, IFNAMSIZ, "%s", copt->match.oifname);

    if (copt->match.af == AF_INET6) {
        if (!ipv6_addr_any(&copt->match.srange.max_addr.in6)) {
            priv->match.srange.min_addr = copt->match.srange.min_addr;
            priv->match.srange.max_addr = copt->match.srange.max_addr;
        }

        if (!ipv6_addr_any(&copt->match.drange.max_addr.in6)) {
            priv->match.drange.min_addr = copt->match.drange.min_addr;
            priv->match.drange.max_addr = copt->match.drange.max_addr;
        }
    } else { /* ipv4 by default */
        if (ntohl(copt->match.srange.max_addr.in.s_addr) != INADDR_ANY) {
            priv->match.srange.min_addr = copt->match.srange.min_addr;
            priv->match.srange.max_addr = copt->match.srange.max_addr;
        }

        if (ntohl(copt->match.drange.max_addr.in.s_addr) != INADDR_ANY) {
            priv->match.drange.min_addr = copt->match.drange.min_addr;
            priv->match.drange.max_addr = copt->match.drange.max_addr;
        }
    }

    if (ntohs(copt->match.srange.max_port)) {
        priv->match.srange.min_port = copt->match.srange.min_port;
        priv->match.srange.max_port = copt->match.srange.max_port;
    }

    if (ntohs(copt->match.drange.max_port)) {
        priv->match.drange.min_port = copt->match.drange.min_port;
        priv->match.drange.max_port = copt->match.drange.max_port;
    }

    if (copt->result.drop) {
        priv->result.drop = copt->result.drop;
    } else {
        /* 0: (TC_H_UNSPEC) is not valid target */
        if (copt->result.sch_id != TC_H_UNSPEC) {
            priv->result.sch_id = copt->result.sch_id;
            priv->result.drop = false; /* exclusive with sch_id */
        }
    }

    return EDPVS_OK;
}

static int match_dump(struct tc_cls *cls, void *arg)
{
    struct match_cls_priv *priv = tc_cls_priv(cls);
    struct tc_cls_match_copt *copt = arg;

    copt->proto = priv->proto;
    copt->match = priv->match;
    copt->result = priv->result;

    return EDPVS_OK;
}

struct tc_cls_ops match_cls_ops = {
    .name       = "match",
    .priv_size  = sizeof(struct match_cls_priv),
    .classify   = match_classify,
    .init       = match_init,
    .change     = match_init,
    .dump       = match_dump,
};
