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

typedef struct hash_netnet_elem {
    union inet_addr ip1;
    uint8_t cidr1;
    union inet_addr ip2;
    uint8_t cidr2;

    /* data not evolved in hash calculation */
    uint16_t port1;
    uint16_t port2;
    char comment[IPSET_MAXCOMLEN];
} elem_t;

static bool
hash_netnet_data_equal(const void *elem1, const void *elem2)
{
    elem_t *e1 = (elem_t *)elem1;
    elem_t *e2 = (elem_t *)elem2;

    return (!memcmp(e1, e2, offsetof(elem_t, port1)) &&
            (e2->port1 == 0 || e1->port1 == e2->port1) &&
            (e2->port2 == 0 || e1->port2 == e2->port2));
}

static void
hash_netnet_do_list(struct ipset_member *member, void *elem, bool comment)
{
    elem_t *e = (elem_t *)elem;

    member->addr = e->ip1;
    member->addr2 = e->ip2;
    member->cidr = e->cidr1;
    member->cidr2 = e->cidr2;
    member->port = ntohs(e->port1);
    member->port2 = ntohs(e->port2);
    if (comment)
        rte_strlcpy(member->comment, e->comment, IPSET_MAXCOMLEN);
}

static uint32_t
hash_netnet_hashkey4(void *data, int len, uint32_t mask)
{
    elem_t *e = (elem_t *)data;

    return (e->ip1.in.s_addr * 31 + e->ip2.in.s_addr * 31 +
            e->cidr1 * 31 + e->cidr2 * 31) & mask;
}

static int
hash_netnet_adt4(int op, struct ipset *set, struct ipset_param *param)
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

    if (op == IPSET_OP_TEST) {
        e.ip1.in.s_addr = param->range.min_addr.in.s_addr;
        e.ip2.in.s_addr = param->range2.min_addr.in.s_addr;
        e.port1 = htons(param->range.min_port);
        e.port2 = htons(param->range2.min_port);

        return adtfn(set, &e, 0);
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
        if (set->comment && param->opcode == IPSET_OP_ADD)
            rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);

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
hash_netnet_test(struct ipset *set, struct ipset_test_param *p)
{
    elem_t e;
    uint16_t *ports, _ports[2];
    struct dp_vs_iphdr *iph = p->iph;

    memset(&e, 0, sizeof(e));

    ports = mbuf_header_pointer(p->mbuf, iph->len, sizeof(_ports), _ports);

    e.ip1 = iph->saddr;
    e.ip2 = iph->daddr;
    e.port1 = ports[0];
    e.port2 = ports[1];

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_netnet_variant4 = {
    .adt = hash_netnet_adt4,
    .test = hash_netnet_test,
    .hash.do_compare = hash_netnet_data_equal,
    .hash.do_netmask = hash_data_netmask4,
    .hash.do_list = hash_netnet_do_list,
    .hash.do_hash = hash_netnet_hashkey4
};

static int
hash_netnet_adt6(int op, struct ipset *set, struct ipset_param *param)
{
    elem_t e;
    ipset_adtfn adtfn = set->type->adtfn[op];

    if (set->family != param->option.family)
        return EDPVS_INVAL;

    memset(&e, 0, sizeof(e));

    e.ip1 = param->range.min_addr;
    e.ip2 = param->range2.min_addr;
    e.cidr1 = param->cidr;
    e.cidr2 = param->cidr2;
    e.port1 = htons(param->range.min_port);
    e.port2 = htons(param->range2.min_port);

    if (set->comment && param->opcode == IPSET_OP_ADD)
        rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);

    return adtfn(set, &e, param->flag);
}

struct ipset_type_variant hash_netnet_variant6 = {
    .adt = hash_netnet_adt6,
    .test = hash_netnet_test,
    .hash.do_compare = hash_netnet_data_equal,
    .hash.do_netmask = hash_data_netmask6,
    .hash.do_list = hash_netnet_do_list,
    .hash.do_hash = jhash_hashkey
};

static int
hash_netnet_create(struct ipset *set, struct ipset_param *param)
{
    hash_create(set, param);
    set->net_count = 2;
    set->dsize = sizeof(elem_t);
    set->hash_len = offsetof(elem_t, port1);

    if (param->option.family == AF_INET)
        set->variant = &hash_netnet_variant4;
    else
        set->variant = &hash_netnet_variant6;

    return EDPVS_OK;
}

struct ipset_type hash_netnet_type = {
    .name       = "hash:net,net",
    .create     = hash_netnet_create,
    .destroy    = hash_destroy,
    .flush      = hash_flush,
    .list       = hash_list,
    .adtfn      = hash_adtfn,
};
