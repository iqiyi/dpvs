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
#include "ipset/ipset.h"
#include "ipset/pfxlen.h"
#include "ipset/ipset_hash.h"

typedef struct hash_netportnetport_elem {
    union inet_addr ip1;
    uint8_t cidr1;
    union inet_addr ip2;
    uint8_t cidr2;
    uint8_t proto;
    uint16_t port1;
    uint16_t port2;

    char comment[IPSET_MAXCOMLEN];
    bool nomatch;
} elem_t;

static int
hash_netportnetport_data_equal(const void *elem1, const void *elem2)
{
    elem_t *e2 = (elem_t *)elem2;

    if (memcmp(elem1, elem2, offsetof(elem_t, comment)))
        return COMPARE_INEQUAL;

    if (e2->nomatch)
        return COMPARE_EQUAL_REJECT;
    return COMPARE_EQUAL_ACCEPT;
}

static void
hash_netportnetport_do_list(struct ipset_member *member, void *elem, bool comment)
{
    elem_t *e = (elem_t *)elem;

    member->addr = e->ip1;
    member->addr2 = e->ip2;
    member->cidr = e->cidr1;
    member->cidr2 = e->cidr2;
    member->proto = e->proto;
    member->port = ntohs(e->port1);
    member->port2 = ntohs(e->port2);
    member->nomatch = e->nomatch;
    if (comment)
        rte_strlcpy(member->comment, e->comment, IPSET_MAXCOMLEN);
}

static uint32_t
hash_netportnetport_hashkey4(void *data, int len, uint32_t mask)
{
    elem_t *e = (elem_t *)data;

    return (e->ip1.in.s_addr * 31 + e->ip2.in.s_addr * 31 +
            e->cidr1 * 31 + e->cidr2 * 31 +
           (((uint32_t)e->port1 << 16) | e->port2)) & mask;
}

static int
hash_netportnetport_adt4(int op, struct ipset *set, struct ipset_param *param)
{
    elem_t e;
    int ret;
    uint16_t port1, port2;
    uint32_t ip1, ip1_to, ip2, ip2_to, ip2_from;
    ipset_adtfn adtfn = set->type->adtfn[op];

    if (set->family != param->option.family)
        return EDPVS_INVAL;

    memset(&e, 0, sizeof(e));

    e.cidr1 = param->cidr;
    e.cidr2 = param->cidr2;
    e.proto = param->proto;

    if (op == IPSET_OP_TEST) {
        e.ip1.in.s_addr = param->range.min_addr.in.s_addr;
        e.ip2.in.s_addr = param->range2.min_addr.in.s_addr;
        e.port1 = htons(param->range.min_port);
        e.port2 = htons(param->range2.min_port);

        return adtfn(set, &e, 0);
    }

    if (param->opcode == IPSET_OP_ADD) {
        if (set->comment)
            rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);
        if (param->option.add.nomatch)
            e.nomatch = true;
    }

    ip1 = ntohl(param->range.min_addr.in.s_addr);
    ip2 = ntohl(param->range2.min_addr.in.s_addr);

    if (e.cidr1) {
        ip_set_mask_from_to(ip1, ip1_to, e.cidr1);
    } else {
        ip1_to = ntohl(param->range.max_addr.in.s_addr);
    }

    if (e.cidr2) {
        ip_set_mask_from_to(ip2, ip2_to, e.cidr2);
    } else {
        ip2_to = ntohl(param->range2.max_addr.in.s_addr);
    }
    ip2_from = ip2;

    do {
        e.ip1.in.s_addr = htonl(ip1);
        ip1 = ip_set_range_to_cidr(ip1, ip1_to, &e.cidr1);
        do {
            e.ip2.in.s_addr = htonl(ip2);
            ip2 = ip_set_range_to_cidr(ip2, ip2_to, &e.cidr2);
            for (port1 = param->range.min_port;
                port1 >= param->range.min_port &&
                port1 <= param->range.max_port; port1++) {
                for (port2 = param->range2.min_port;
                    port2 >= param->range2.min_port &&
                    port2 <= param->range2.max_port; port2++) {
                    e.port1 = htons(port1);
                    e.port2 = htons(port2);
                    ret = adtfn(set, &e, param->flag);
                    if (ret)
                        return ret;
                }
            }
        } while(ip2++ < ip2_to);
        ip2 = ip2_from;
    } while(ip1++ < ip1_to);

    return EDPVS_OK;
}

static int
hash_netportnetport_test4(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
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

    e.ip1.in.s_addr = ip4hdr->src_addr;
    e.ip2.in.s_addr = ip4hdr->dst_addr;
    if (l4hdr) {
        e.port1 = l4hdr->src_port;
        e.port2 = l4hdr->dst_port;
    }

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_netportnetport_variant4 = {
    .adt = hash_netportnetport_adt4,
    .test = hash_netportnetport_test4,
    .hash.do_compare = hash_netportnetport_data_equal,
    .hash.do_netmask = hash_data_netmask4,
    .hash.do_list = hash_netportnetport_do_list,
    .hash.do_hash = hash_netportnetport_hashkey4
};

static int
hash_netportnetport_adt6(int op, struct ipset *set, struct ipset_param *param)
{
    uint16_t port1, port2;
    int ret;
    elem_t e;
    ipset_adtfn adtfn = set->type->adtfn[op];

    if (set->family != param->option.family)
        return EDPVS_INVAL;

    memset(&e, 0, sizeof(e));

    e.ip1 = param->range.min_addr;
    e.ip2 = param->range2.min_addr;
    e.cidr1 = param->cidr;
    e.cidr2 = param->cidr2;
    e.proto = param->proto;

    if (param->opcode == IPSET_OP_TEST) {
        e.port1 = htons(param->range.min_port);
        e.port2 = htons(param->range2.min_port);
        return adtfn(set, &e, 0);
    }

    if ( param->opcode == IPSET_OP_ADD) {
        if (set->comment)
            rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);
        if (param->option.add.nomatch)
            e.nomatch = true;
    }

    if (e.cidr1)
        ip6_netmask(&e.ip1, e.cidr1);
    if (e.cidr2)
        ip6_netmask(&e.ip2, e.cidr2);

    for (port1 = param->range.min_port; port1 >= param->range.min_port &&
            port1 <= param->range.max_port; port1++) {
        for (port2 = param->range2.min_port; port2 >= param->range2.min_port &&
                port2 <= param->range2.max_port; port2++) {
            e.port1 = htons(port1);
            e.port2 = htons(port2);
            ret = adtfn(set, &e, param->flag);
            if (ret)
                return ret;
        }
    }
    return EDPVS_OK;
}

static int
hash_netportnetport_test6(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
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

    memcpy(&e.ip1, ip6hdr->src_addr, sizeof(e.ip1));
    memcpy(&e.ip2, ip6hdr->dst_addr, sizeof(e.ip2));
    if (l4hdr) {
        e.port1 = l4hdr->src_port;
        e.port2 = l4hdr->dst_port;
    }

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_netportnetport_variant6 = {
    .adt = hash_netportnetport_adt6,
    .test = hash_netportnetport_test6,
    .hash.do_compare = hash_netportnetport_data_equal,
    .hash.do_netmask = hash_data_netmask6,
    .hash.do_list = hash_netportnetport_do_list,
    .hash.do_hash = jhash_hashkey
};

static int
hash_netportnetport_create(struct ipset *set, struct ipset_param *param)
{
    hash_create(set, param);
    set->net_count = 2;
    set->dsize = sizeof(elem_t);
    set->hash_len = offsetof(elem_t, comment);

    if (param->option.family == AF_INET6)
        set->variant = &hash_netportnetport_variant6;
    else
        set->variant = &hash_netportnetport_variant4;

    return EDPVS_OK;
}

struct ipset_type hash_netportnetport_type = {
    .name       = "hash:net,port,net,port",
    .create     = hash_netportnetport_create,
    .destroy    = hash_destroy,
    .flush      = hash_flush,
    .list       = hash_list,
    .adtfn      = hash_adtfn,
};
