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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "ipset/ipset_hash.h"
#include "ipset/pfxlen.h"

typedef struct hash_netport_elem {
    union inet_addr ip;
    uint8_t cidr;
    uint8_t proto;
    uint16_t port;

    /* data not evolved in hash calculation */
    char comment[IPSET_MAXCOMLEN];
    bool nomatch;
} elem_t;

static int
hash_netport_data_equal(const void *elem1, const void *elem2)
{
    elem_t *e2 = (elem_t *)elem2;

    if (memcmp(elem1, elem2, offsetof(elem_t, comment)))
        return COMPARE_INEQUAL;
    if (e2->nomatch)
        return COMPARE_EQUAL_REJECT;
    return COMPARE_EQUAL_ACCEPT;
}

static void
hash_netport_do_list(struct ipset_member *member, void *elem, bool comment)
{
    elem_t *e = (elem_t *)elem;

    member->addr = e->ip;
    member->cidr = e->cidr;
    member->port = ntohs(e->port);
    member->proto = e->proto;
    member->nomatch = e->nomatch;
    
    if (comment)
        rte_strlcpy(member->comment, e->comment, IPSET_MAXCOMLEN);
}

static uint32_t
hash_netport_hashkey4(void *data, int len, uint32_t mask)
{
    elem_t *e = (elem_t *)data;

    return (e->ip.in.s_addr * 31 + (((uint32_t)e->port << 16) |
                (((uint32_t)e->proto) << 8) | (uint32_t)e->cidr)) & mask;
}

static int
hash_netport_adt4(int op, struct ipset *set, struct ipset_param *param)
{
    elem_t e;
    int ret;
    uint16_t port;
    uint32_t ip, ip_to;
    ipset_adtfn adtfn = set->type->adtfn[op];

    if (set->family != param->option.family)
        return EDPVS_INVAL;

    memset(&e, 0, sizeof(e));

    e.cidr = param->cidr;
    e.proto = param->proto;

    if (op == IPSET_OP_TEST) {
        e.ip.in.s_addr = param->range.min_addr.in.s_addr;
        e.port = htons(param->range.min_port);
        return adtfn(set, &e, 0);
    }

    if (op == IPSET_OP_ADD) {
        if (param->option.add.nomatch)
            e.nomatch = true;
        if (set->comment)
            rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);
    }

    ip = ntohl(param->range.min_addr.in.s_addr);
    if (e.cidr) {
        ip_set_mask_from_to(ip, ip_to, e.cidr);
    } else {
        ip_to = ntohl(param->range.max_addr.in.s_addr);
    }

    do {
        e.ip.in.s_addr = htonl(ip);
        ip = ip_set_range_to_cidr(ip, ip_to, &e.cidr);
        for (port = param->range.min_port; 
             port >= param->range.min_port &&
             port <= param->range.max_port; port++) {
            e.port = htons(port);
            ret = adtfn(set, &e, param->flag);
            if (ret)
                return ret;
        }
    } while(ip++ < ip_to);

    return EDPVS_OK;
}

static int
hash_netport_test4(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
{
    elem_t e;
    uint16_t proto;
    struct rte_ipv4_hdr *ip4hdr;
    struct rte_udp_hdr *l4hdr = NULL;

    if (set->family != AF_INET || mbuf_address_family(mbuf) != AF_INET)
        return 0;

    proto = mbuf_protocol(mbuf);
    if (!hash_proto_support(proto))
        return 0;

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        l4hdr = mbuf_header_l4(mbuf);
        if (unlikely(!l4hdr))
            return 0;
    }

    ip4hdr = mbuf_header_l3(mbuf);
    if (unlikely(!ip4hdr))
        return 0;

    memset(&e, 0, sizeof(e));
    e.proto = proto;
    if (dst_match) {
        e.ip.in.s_addr = ip4hdr->dst_addr;
        if (l4hdr)
            e.port = l4hdr->dst_port;
    } else {
        e.ip.in.s_addr = ip4hdr->src_addr;
        if (l4hdr)
            e.port = l4hdr->src_port;
    }

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_netport_variant4 = {
    .adt = hash_netport_adt4,
    .test = hash_netport_test4,
    .hash.do_compare = hash_netport_data_equal,
    .hash.do_netmask = hash_data_netmask4,
    .hash.do_list = hash_netport_do_list,
    .hash.do_hash = hash_netport_hashkey4,
};

static int
hash_netport_adt6(int op, struct ipset *set, struct ipset_param *param)
{
    int ret;
    uint16_t port;
    elem_t e;
    ipset_adtfn adtfn = set->type->adtfn[op];

    if (set->family != param->option.family)
        return EDPVS_INVAL;

    memset(&e, 0, sizeof(e));

    e.ip = param->range.min_addr;
    e.cidr = param->cidr;
    e.proto = param->proto;

    if (op == IPSET_OP_TEST) {
        e.port = htons(param->range.min_port);
        return adtfn(set, &e, 0);
    }

    if (op == IPSET_OP_ADD) {
        if (param->option.add.nomatch)
            e.nomatch = true;
        if (set->comment)
            rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);
    }

    if (e.cidr)
        ip6_netmask(&e.ip, e.cidr);

    for (port = param->range.min_port; port >= param->range.min_port &&
            port <= param->range.max_port; port++) {
        e.port = htons(port);
        ret = adtfn(set, &e, param->flag);
        if (ret)
            return ret;
    }

    return EDPVS_OK;
}

static int
hash_netport_test6(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
{
    elem_t e;
    uint16_t proto;
    struct rte_ipv6_hdr *ip6hdr;
    struct rte_udp_hdr *l4hdr = NULL;

    if (set->family != AF_INET6 || mbuf_address_family(mbuf) != AF_INET6)
        return 0;

    proto = mbuf_protocol(mbuf);
    if (!hash_proto_support(proto))
        return 0;

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        l4hdr = mbuf_header_l4(mbuf);
        if (unlikely(!l4hdr))
            return 0;
    }

    ip6hdr = mbuf_header_l3(mbuf);
    if (unlikely(!ip6hdr))
        return 0;

    memset(&e, 0, sizeof(e));
    e.proto = proto;
    if (dst_match) {
        memcpy(&e.ip, ip6hdr->dst_addr, sizeof(e.ip));
        if (l4hdr)
            e.port = l4hdr->dst_port;
    } else {
        memcpy(&e.ip, ip6hdr->src_addr, sizeof(e.ip));
        if (l4hdr)
            e.port = l4hdr->src_port;
    }

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_netport_variant6 = {
    .adt = hash_netport_adt6,
    .test = hash_netport_test6,
    .hash.do_compare = hash_netport_data_equal,
    .hash.do_netmask = hash_data_netmask6,
    .hash.do_list = hash_netport_do_list,
    .hash.do_hash = jhash_hashkey
};

static int
hash_netport_create(struct ipset *set, struct ipset_param *param)
{
    hash_create(set, param);
    set->net_count = 1;
    set->dsize = sizeof(elem_t);
    set->hash_len = offsetof(elem_t, comment);

    if (param->option.family == AF_INET6)
        set->variant = &hash_netport_variant6;
    else
        set->variant = &hash_netport_variant4;

    return EDPVS_OK;
}

struct ipset_type hash_netport_type = {
    .name       = "hash:net,port",
    .create     = hash_netport_create,
    .destroy    = hash_destroy,
    .flush      = hash_flush,
    .list       = hash_list,
    .adtfn      = hash_adtfn,
};
