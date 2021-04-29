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

typedef struct hash_net_elem {
    union inet_addr ip;
    uint8_t cidr;

    char comment[IPSET_MAXCOMLEN];
} elem_t;

static bool
hash_net_data_equal4(const void *elem1, const void *elem2)
{
    elem_t *e1 = (elem_t *)elem1;
    elem_t *e2 = (elem_t *)elem2;

    return e1->ip.in.s_addr == e2->ip.in.s_addr &&
           e1->cidr == e2->cidr;
}

static void
hash_net_do_list(struct ipset_member *member, void *elem, bool comment)
{
    elem_t *e = (elem_t *)elem;

    member->addr = e->ip;
    member->cidr = e->cidr;
    
    if (comment)
        rte_strlcpy(member->comment, e->comment, IPSET_MAXCOMLEN);
}

static uint32_t
hash_net_hashkey4(void *data, int len, uint32_t mask)
{
    elem_t *e = (elem_t *)data;

    return (e->ip.in.s_addr * 31 + e->cidr * 31) & mask;
}

static int
hash_net_adt4(int op, struct ipset *set, struct ipset_param *param)
{
    elem_t e;
    int ret;
    uint32_t ip, ip_to;
    ipset_adtfn adtfn = set->type->adtfn[op];

    if (set->family != param->option.family)
        return EDPVS_INVAL;

    memset(&e, 0, sizeof(e));

    e.cidr = param->cidr;
    if (op == IPSET_OP_TEST) {
        e.ip.in.s_addr = param->range.min_addr.in.s_addr;

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

        ret = adtfn(set, &e, param->flag);
        if (ret)
            return ret;
    } while(ip++ < ip_to);

    return EDPVS_OK;
}

static int
hash_net_test(struct ipset *set, struct ipset_test_param *p)
{
    elem_t e;

    memset(&e, 0, sizeof(e));

    if (p->direction == 1)
        e.ip = p->iph->saddr;
    else
        e.ip = p->iph->daddr;

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_net_variant4 = {
    .adt = hash_net_adt4,
    .test = hash_net_test,
    .hash.do_compare = hash_net_data_equal4,
    .hash.do_netmask = hash_data_netmask4,
    .hash.do_list = hash_net_do_list,
    .hash.do_hash = hash_net_hashkey4,
};

static bool
hash_net_data_equal6(const void *elem1, const void *elem2)
{
    return !memcmp(elem1, elem2, offsetof(elem_t, comment));
}

static int
hash_net_adt6(int op, struct ipset *set, struct ipset_param *param)
{
    elem_t e;
    ipset_adtfn adtfn = set->type->adtfn[op];

    if (set->family != param->option.family)
        return EDPVS_INVAL;

    memset(&e, 0, sizeof(e));

    e.ip = param->range.min_addr;
    e.cidr = param->cidr;

    if (set->comment && param->opcode == IPSET_OP_ADD)
        rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);

    return adtfn(set, &e, param->flag);
}

struct ipset_type_variant hash_net_variant6 = {
    .adt = hash_net_adt6,
    .test = hash_net_test,
    .hash.do_compare = hash_net_data_equal6,
    .hash.do_netmask = hash_data_netmask6,
    .hash.do_list = hash_net_do_list,
    .hash.do_hash = jhash_hashkey
};

static int
hash_net_create(struct ipset *set, struct ipset_param *param)
{
    hash_create(set, param);
    set->net_count = 1;
    set->dsize = sizeof(elem_t);
    set->hash_len = offsetof(elem_t, comment);

    if (param->option.family == AF_INET)
        set->variant = &hash_net_variant4;
    else
        set->variant = &hash_net_variant6;

    return EDPVS_OK;
}

struct ipset_type hash_net_type = {
    .name       = "hash:net",
    .create     = hash_net_create,
    .destroy    = hash_destroy,
    .flush      = hash_flush,
    .list       = hash_list,
    .adtfn      = hash_adtfn,
};
