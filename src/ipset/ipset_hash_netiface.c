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

typedef struct hash_netiface_elem {
    union inet_addr ip;
    uint8_t cidr;
    uint8_t proto;
    uint16_t iface;

    /* data not evolved in hash calculation */
    struct netif_port *dev;
    uint16_t port;
    char comment[IPSET_MAXCOMLEN];
} elem_t;

static bool
hash_netiface_data_equal(const void *adt_elem, const void *set_elem)
{
    elem_t *e1 = (elem_t *)adt_elem;
    elem_t *e2 = (elem_t *)set_elem;

    return !memcmp(e1, e2, offsetof(elem_t, dev)) &&
           (e2->port == 0 || e1->port == e2->port);
}

static void
hash_netiface_do_list(struct ipset_member *member, void *elem, bool comment)
{
    elem_t *e = (elem_t *)elem;

    member->addr = e->ip;
    member->cidr = e->cidr;
    member->port = ntohs(e->port);
    member->proto = e->proto;
    rte_strlcpy(member->iface, e->dev->name, IFNAMSIZ);
    
    if (comment)
        rte_strlcpy(member->comment, e->comment, IPSET_MAXCOMLEN);
}

static uint32_t
hash_netiface_hashkey4(void *data, int len, uint32_t mask)
{
    elem_t *e = (elem_t *)data;

    return (e->ip.in.s_addr * 31 + e->cidr * 31 + (e->iface | e->proto)) & mask;
}

static int
hash_netiface_adt4(int op, struct ipset *set, struct ipset_param *param)
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
    e.dev = netif_port_get_by_name(param->iface);
    if (unlikely(e.dev == NULL))
        return EDPVS_INVAL;
    e.iface = e.dev->id;

    if (op == IPSET_OP_TEST) {
        e.ip.in.s_addr = param->range.min_addr.in.s_addr;
        e.port = htons(param->range.min_port);

        return adtfn(set, &e, 0);
    }

    ip = ntohl(param->range.min_addr.in.s_addr);

    if (e.cidr) {
        ip_set_mask_from_to(ip, ip_to, e.cidr);
    } else {
        ip_to = ntohl(param->range.max_addr.in.s_addr);
    }

    do {
        if (set->comment && param->opcode == IPSET_OP_ADD)
            rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);

        e.ip.in.s_addr = htonl(ip);
        ip = ip_set_range_to_cidr(ip, ip_to, &e.cidr);

        for (port = param->range.min_port; 
             port >= param->range.min_port &&
             port <= param->range.max_port; port++) {

            e.port = htons(port);
            ret = adtfn(set, &e, param->flag);
        }
        if (ret)
            return ret;
    } while(ip++ < ip_to);

    return EDPVS_OK;
}

static int
hash_netiface_test(struct ipset *set, struct ipset_test_param *p)
{
    elem_t e;
    uint16_t *ports, _ports[2];
    struct dp_vs_iphdr *iph = p->iph;

    memset(&e, 0, sizeof(e));

    e.iface = p->mbuf->port;
    e.proto = iph->proto;

    if (e.proto == IPPROTO_ICMP || e.proto == IPPROTO_ICMPV6) {
        /* for ICMP, port is 0 */
        e.ip = p->direction == 1? iph->saddr : iph->daddr;
        return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
    }

    ports = mbuf_header_pointer(p->mbuf, iph->len, sizeof(_ports), _ports);

    if (p->direction == 1) {
        e.ip = iph->saddr;
        e.port = ports[0];
    } else {
        e.ip = iph->daddr;
        e.port = ports[1];
    }

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_netiface_variant4 = {
    .adt = hash_netiface_adt4,
    .test = hash_netiface_test,
    .hash.do_compare = hash_netiface_data_equal,
    .hash.do_netmask = hash_data_netmask4,
    .hash.do_list = hash_netiface_do_list,
    .hash.do_hash = hash_netiface_hashkey4,
};

static int
hash_netiface_adt6(int op, struct ipset *set, struct ipset_param *param)
{
    elem_t e;
    ipset_adtfn adtfn = set->type->adtfn[op];

    if (set->family != param->option.family)
        return EDPVS_INVAL;

    memset(&e, 0, sizeof(e));

    e.ip = param->range.min_addr;
    e.cidr = param->cidr;
    e.proto = param->proto;
    e.port = htons(param->range.min_port);
    e.dev = netif_port_get_by_name(param->iface);
    if (unlikely(e.dev == NULL))
        return EDPVS_NOTEXIST;
    e.iface = e.dev->id;

    if (set->comment && param->opcode == IPSET_OP_ADD)
        rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);

    return adtfn(set, &e, param->flag);
}

struct ipset_type_variant hash_netiface_variant6 = {
    .adt = hash_netiface_adt6,
    .test = hash_netiface_test,
    .hash.do_compare = hash_netiface_data_equal,
    .hash.do_netmask = hash_data_netmask6,
    .hash.do_list = hash_netiface_do_list,
    .hash.do_hash = jhash_hashkey
};

static int
hash_netiface_create(struct ipset *set, struct ipset_param *param)
{
    hash_create(set, param);
    set->net_count = 1;
    set->dsize = sizeof(elem_t);
    set->hash_len = offsetof(elem_t, dev);

    if (param->option.family == AF_INET)
        set->variant = &hash_netiface_variant4;
    else
        set->variant = &hash_netiface_variant6;

    return EDPVS_OK;
}

struct ipset_type hash_netiface_type = {
    .name       = "hash:net,iface",
    .create     = hash_netiface_create,
    .destroy    = hash_destroy,
    .flush      = hash_flush,
    .list       = hash_list,
    .adtfn      = hash_adtfn,
};
