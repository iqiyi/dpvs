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
#include "ipset/ipset_hash.h"
#include "ipset/pfxlen.h"

typedef struct hash_ipportip_elem4 {
    uint32_t ip1;
    uint32_t ip2;
    uint16_t port;
    uint8_t proto;

    char comment[IPSET_MAXCOMLEN];
} elem4_t;

static int
hash_ipportip_data_equal4(const void *elem1, const void *elem2)
{
    elem4_t *e1 = (elem4_t *)elem1;
    elem4_t *e2 = (elem4_t *)elem2;

    return e1->ip1 == e2->ip1 && e1->ip2 == e2->ip2 &&
           e1->port == e2->port && e1->proto == e2->proto;
}

static void
hash_ipportip_do_list4(struct ipset_member *member, void *elem, bool comment)
{
    elem4_t *e = (elem4_t *)elem;

    member->port = ntohs(e->port);
    member->proto = e->proto;
    member->addr.in.s_addr = e->ip1;
    member->addr2.in.s_addr = e->ip2;
    if (comment)
        rte_strlcpy(member->comment, e->comment, IPSET_MAXCOMLEN);
}

static uint32_t
hash_ipportip_hashkey4(void *data, int len, uint32_t mask)
{
    elem4_t *e = (elem4_t *)data;

    return (e->ip1 * 31 + e->ip2 * 31 + e->port * 31 + e->proto) & mask;
}

static int
hash_ipportip_adt4(int opcode, struct ipset *set, struct ipset_param *param)
{
    elem4_t e;
    int ret;
    uint16_t port;
    uint32_t ip, ip_to, ip2, ip2_to;
    ipset_adtfn adtfn = set->type->adtfn[opcode];

    if (set->family != param->option.family)
        return EDPVS_INVAL;

    memset(&e, 0, sizeof(e));

    if (opcode == IPSET_OP_TEST) {
        e.ip1 = param->range.min_addr.in.s_addr;
        e.ip2 = param->range2.min_addr.in.s_addr;
        e.proto = param->proto;
        e.port = htons(param->range.min_port);

        return adtfn(set, &e, 0);
    }

    e.proto = param->proto;
    if (set->comment && opcode == IPSET_OP_ADD)
        rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);

    ip = ntohl(param->range.min_addr.in.s_addr);
    if (param->cidr) {
        ip_set_mask_from_to(ip, ip_to, param->cidr);
    } else {
        ip_to = ntohl(param->range.max_addr.in.s_addr);
    }
    for (; ip <= ip_to; ip++) {
        e.ip1 = htonl(ip);

        for (port = param->range.min_port; port >= param->range.min_port &&
                port <= param->range.max_port; port++) {
            e.port = htons(port);

            ip2 = ntohl(param->range2.min_addr.in.s_addr);
            if (param->cidr2) {
                ip_set_mask_from_to(ip2, ip2_to, param->cidr2);
            } else {
                ip2_to = ntohl(param->range2.max_addr.in.s_addr);
            }
            for (; ip2 <= ip2_to; ip2++) {
                e.ip2 = ntohl(ip2);
                ret = adtfn(set, &e, param->flag);
                if (ret)
                    return ret;
            }
        }
    }
    return EDPVS_OK;
}

static int
hash_ipportip_test4(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
{
    elem4_t e;
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
    e.ip1 = ip4hdr->src_addr;
    e.ip2 = ip4hdr->dst_addr;

    if (l4hdr) {
        if (dst_match)
            e.port = l4hdr->dst_port;
        else
            e.port = l4hdr->src_port;
    }

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_ipportip_variant4 = {
    .adt = hash_ipportip_adt4,
    .test = hash_ipportip_test4,
    .hash.do_compare = hash_ipportip_data_equal4,
    .hash.do_list = hash_ipportip_do_list4,
    .hash.do_hash = hash_ipportip_hashkey4
};

typedef struct hash_ipportip_elem6 {
    struct in6_addr ip1;
    struct in6_addr ip2;
    uint16_t port;
    uint8_t proto;

    char comment[IPSET_MAXCOMLEN];
} elem6_t;

static int
hash_ipportip_data_equal6(const void *elem1, const void *elem2)
{
    elem6_t *e1 = (elem6_t *)elem1;
    elem6_t *e2 = (elem6_t *)elem2;

    return !memcmp(e1->ip1.s6_addr, e2->ip1.s6_addr, 16) &&
           !memcmp(e1->ip2.s6_addr, e2->ip2.s6_addr, 16) &&
           e1->port == e2->port &&
           e1->proto == e2->proto;
}

static void
hash_ipportip_do_list6(struct ipset_member *member, void *elem, bool comment)
{
    elem6_t *e = (elem6_t *)elem;

    member->port = ntohs(e->port);
    member->proto = e->proto;
    member->addr.in6 = e->ip1;
    member->addr2.in6 = e->ip2;
    if (comment)
        rte_strlcpy(member->comment, e->comment, IPSET_MAXCOMLEN);
}

static int
hash_ipportip_adt6(int opcode, struct ipset *set, struct ipset_param *param)
{
    int ret;
    uint16_t port;
    elem6_t e;
    ipset_adtfn adtfn = set->type->adtfn[opcode];

    if (set->family != param->option.family)
        return EDPVS_INVAL;

    memset(&e, 0, sizeof(e));

    e.ip1 = param->range.min_addr.in6;
    e.ip2 = param->range2.min_addr.in6;
    e.proto = param->proto;

    if (opcode == IPSET_OP_TEST) {
        e.port = htons(param->range.min_port);
        return adtfn(set, &e, 0);
    }

    if (set->comment && opcode == IPSET_OP_ADD)
        rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);

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
hash_ipportip_test6(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
{
    elem6_t e;
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
    memcpy(&e.ip1, ip6hdr->src_addr, sizeof(e.ip1));
    memcpy(&e.ip2, ip6hdr->dst_addr, sizeof(e.ip2));

    if (l4hdr) {
        if (dst_match)
            e.port = l4hdr->dst_port;
        else
            e.port = l4hdr->src_port;
    }

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_ipportip_variant6 = {
    .adt = hash_ipportip_adt6,
    .test = hash_ipportip_test6,
    .hash.do_compare = hash_ipportip_data_equal6,
    .hash.do_list = hash_ipportip_do_list6,
    .hash.do_hash = jhash_hashkey
};

static int
hash_ipportip_create(struct ipset *set, struct ipset_param *param)
{
    hash_create(set, param);

    if (param->option.family == AF_INET6) {
        set->dsize = sizeof(elem6_t);
        set->hash_len = offsetof(elem6_t, comment);
        set->variant = &hash_ipportip_variant6;
    } else {
        set->dsize = sizeof(elem4_t);
        set->hash_len = offsetof(elem4_t, comment);
        set->variant = &hash_ipportip_variant4;
    }

    return EDPVS_OK;
}

struct ipset_type hash_ipportip_type = {
    .name       = "hash:ip,port,ip",
    .create     = hash_ipportip_create,
    .destroy    = hash_destroy,
    .flush      = hash_flush,
    .list       = hash_list,
    .adtfn      = hash_adtfn,
};
