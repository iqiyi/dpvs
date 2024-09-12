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

typedef struct hash_ip_elem4 {
    uint32_t ip;

    char comment[IPSET_MAXCOMLEN];
} elem4_t;

static int
hash_ip_data_equal4(const void *e1, const void *e2)
{
    return ((elem4_t *)e1)->ip == ((elem4_t *)e2)->ip;
}

static void
hash_ip_do_list4(struct ipset_member *member, void *elem, bool comment)
{
    elem4_t *e = (elem4_t *)elem;

    member->addr.in.s_addr = e->ip;
    if (comment)
        rte_strlcpy(member->comment, e->comment, IPSET_MAXCOMLEN);
}

static uint32_t
hash_ip_hashkey4(void *data, int len, uint32_t mask)
{
    return (((elem4_t *)data)->ip * 31) & mask;
}

static int
hash_ip_adt4(int opcode, struct ipset *set, struct ipset_param *param)
{
    elem4_t e;
    int ret;
    uint32_t ip, ip_to;

    ipset_adtfn adtfn = set->type->adtfn[opcode];

    if (param->option.family != AF_INET)
        return EDPVS_INVAL;

    if (opcode == IPSET_OP_TEST) {
        e.ip = param->range.min_addr.in.s_addr;

        return adtfn(set, &e, 0);
    }

    if (set->comment && opcode == IPSET_OP_ADD)
        rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);

    ip = ntohl(param->range.min_addr.in.s_addr);
    if (param->cidr) {
        ip_set_mask_from_to(ip, ip_to, param->cidr);
    } else {
        ip_to = ntohl(param->range.max_addr.in.s_addr);
    }
    for (; ip <= ip_to; ip++) {
        e.ip = htonl(ip);
        ret = adtfn(set, &e, param->flag);
        if (ret)
            return ret;
    }
    return EDPVS_OK;
}

static int
hash_ip_test4(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
{
    elem4_t e;
    struct rte_ipv4_hdr *ip4hdr;

    if (set->family != AF_INET || mbuf_address_family(mbuf) != AF_INET)
        return 0;

    ip4hdr = mbuf_header_l3(mbuf);
    if (unlikely(!ip4hdr))
        return 0;

    memset(&e, 0, sizeof(e));

    if (dst_match)
        e.ip = ip4hdr->dst_addr;
    else
        e.ip = ip4hdr->src_addr;

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_ip_variant4 = {
    .adt = hash_ip_adt4,
    .test = hash_ip_test4,
    .hash.do_compare = hash_ip_data_equal4,
    .hash.do_list = hash_ip_do_list4,
    .hash.do_hash = hash_ip_hashkey4
};

typedef struct hash_ip_elem6 {
    struct in6_addr ip;
    
    char comment[IPSET_MAXNAMELEN];
} elem6_t;

static int
hash_ip_data_equal6(const void *e1, const void *e2)
{
    return inet_addr_equal(AF_INET6, e1, e2);
}

static void
hash_ip_do_list6(struct ipset_member *member, void *elem, bool comment)
{
    elem6_t *e = (elem6_t *)elem;

    member->addr.in6 = e->ip;
    if (comment)
        rte_strlcpy(member->comment, e->comment, IPSET_MAXCOMLEN);
}

static int
hash_ip_adt6(int opcode, struct ipset *set, struct ipset_param *param)
{
    elem6_t e;

    ipset_adtfn adtfn = set->type->adtfn[opcode];

    if (param->option.family != AF_INET6)
        return EDPVS_INVAL;

    e.ip = param->range.min_addr.in6;

    if (set->comment && opcode == IPSET_OP_ADD)
        rte_strlcpy(e.comment, param->comment, IPSET_MAXCOMLEN);

    return adtfn(set, &e, param->flag);
}

static int
hash_ip_test6(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
{
    elem6_t e;
    struct rte_ipv6_hdr *ip6hdr;

    if (set->family != AF_INET6 || mbuf_address_family(mbuf) != AF_INET6)
        return 0;

    ip6hdr = mbuf_header_l3(mbuf);
    if (unlikely(!ip6hdr))
        return 0;

    memset(&e, 0, sizeof(e));

    if (dst_match)
        memcpy(&e.ip, ip6hdr->dst_addr, sizeof(e.ip));
    else
        memcpy(&e.ip, ip6hdr->src_addr, sizeof(e.ip));

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant hash_ip_variant6 = {
    .adt = hash_ip_adt6,
    .test = hash_ip_test6,
    .hash.do_compare = hash_ip_data_equal6,
    .hash.do_list = hash_ip_do_list6,
    .hash.do_hash = jhash_hashkey
};

static int
hash_ip_create(struct ipset *set, struct ipset_param *param)
{
    hash_create(set, param);
    if (param->option.family == AF_INET6) {
        set->dsize = sizeof(elem6_t);
        set->hash_len = offsetof(elem6_t, comment);
        set->variant = &hash_ip_variant6;
    } else {
        set->dsize = sizeof(elem4_t);
        set->hash_len = offsetof(elem4_t, comment);
        set->variant = &hash_ip_variant4;
    }

    return EDPVS_OK;
}

struct ipset_type hash_ip_type = {
    .name       = "hash:ip",
    .create     = hash_ip_create,
    .destroy    = hash_destroy,
    .flush      = hash_flush,
    .list       = hash_list,
    .adtfn      = hash_adtfn,
};
