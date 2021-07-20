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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "netif.h"
#include "vlan.h"
#include "ipv4.h"
#include "ipv6.h"
#include "tc/tc.h"
#include "tc/sch.h"
#include "tc/cls.h"
#include "linux_ipv6.h"
#include "ipv6.h"
#include "conf/match.h"
#include "conf/tc.h"
#include "ipset/ipset.h"

struct set_cls_priv {
    struct tc_cls         *cls;

    struct ipset          *set;        
    struct tc_cls_result  result;
};

static int fill_iphdr(int af, struct rte_mbuf *mbuf,
                            struct dp_vs_iphdr *iph)
{
    if (af == AF_INET) {
        struct ipv4_hdr *ip4h = ip4_hdr(mbuf);
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

static int set_classify(struct tc_cls *cls, struct rte_mbuf *mbuf,
                          struct tc_cls_result *result)
{    
    struct set_cls_priv *priv = tc_cls_priv(cls);
    struct ether_hdr *eh = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    int offset = sizeof(*eh);
    __be16 pkt_type = eh->ether_type;
    struct vlan_ethhdr *veh;
    int direction;
    struct dp_vs_iphdr iph;
    int err = TC_ACT_RECLASSIFY; /* by default */
    struct ipset* set = priv->set;
    struct ipset_test_param param;

    /* support IPv4 and 802.1q/IPv4 */
l2parse:
    switch (ntohs(pkt_type)) {
    case ETH_P_IP:
        if (set->family != AF_INET)
            goto done;

        if (mbuf_may_pull(mbuf, offset + sizeof(struct iphdr)) != 0) {
            err = TC_ACT_SHOT;
            goto done;
        }
        break;

    case ETH_P_IPV6:
        if (set->family != AF_INET6)
            goto done;

        if (mbuf_may_pull(mbuf, offset + sizeof(struct ip6_hdr)) != 0) {
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

    direction = cls->sch->flags & QSCH_F_INGRESS? 1 : -1;
    /* for IPset type containing MAC element */
    mbuf->userdata = direction == 1? 
        eh->s_addr.addr_bytes : eh->d_addr.addr_bytes;

    rte_pktmbuf_adj(mbuf, offset);
    fill_iphdr(set->family, mbuf, &iph);
    param.iph = &iph;
    param.mbuf = mbuf;
    param.direction = direction;

    if (elem_in_set(set, &param)) {
        goto match;
    } else {
        rte_pktmbuf_prepend(mbuf, offset);
        return err;
    }

match:
    /* all matchs */
    rte_pktmbuf_prepend(mbuf, offset);
    *result = priv->result;
    err = TC_ACT_OK;

done:
    return err;
}

static int set_init(struct tc_cls *cls, const void *arg)
{
    struct set_cls_priv *priv = tc_cls_priv(cls);
    const struct tc_cls_ipset_copt *copt = arg;

    if (!arg)
        return EDPVS_INVAL;
    
    priv->set = ipset_get((char *)copt->setname);
    if (!priv->set)
        return EDPVS_NOTEXIST;
    
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

static int set_dump(struct tc_cls *cls, void *arg)
{
    struct set_cls_priv *priv = tc_cls_priv(cls);
    struct tc_cls_ipset_copt *copt = arg;

    rte_strlcpy(copt->setname, priv->set->name, 32);
    copt->result = priv->result;

    return EDPVS_OK;
}

static void set_destroy(struct tc_cls *cls)
{
    struct set_cls_priv *priv = tc_cls_priv(cls);

    ipset_put(priv->set);
}

struct tc_cls_ops ipset_cls_ops = {
    .name       = "ipset",
    .priv_size  = sizeof(struct set_cls_priv),
    .classify   = set_classify,
    .init       = set_init,
    .change     = set_init,
    .dump       = set_dump,
    .destroy    = set_destroy,
};
