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
#include "ipset/bitops.h"
#include "ipset/ipset.h"
#include "ipset/pfxlen.h"
#include "ipset/ipset_bitmap.h"

struct bitmap_ip {
    size_t size;                /* total size */
    uint32_t elements;          /* number of max elements in the set */
    unsigned long *members;     /* the set members */
    unsigned char *extensions;  /* the extensions for each member */

    uint32_t first_ip;          /* host byte order, included in range */
    uint32_t last_ip;           /* host byte order, included in range */
    uint8_t cidr;               /* range cidr */
};

typedef struct bitmap_elem elem_t;

typedef struct bitmap_ip_ext {
    char comment[IPSET_MAXCOMLEN];
} ext_t;

static uint32_t
ip_to_id(struct bitmap_ip *m, uint32_t ip)
{
    return ip - m->first_ip;
}

static int
bitmap_ip_do_del(struct bitmap_elem *e, struct bitmap_map *map)
{
    return test_and_clear_bit(e->id, map->members);
}

static int
bitmap_ip_do_test(struct bitmap_elem *e, struct bitmap_map *map, size_t dsize)
{
    return test_bit(e->id, map->members);
}

static void
bitmap_ip_do_list(struct ipset *set, struct ipset_bitmap_header *header,
                struct ipset_member *members)
{
    struct bitmap_ip *map = set->data;
    struct ipset_member *member;
    int id;
    ext_t *ext;

    header->range.min_addr.in.s_addr = htonl(map->first_ip);
    if (map->cidr)
        header->cidr = map->cidr;
    else
        header->range.max_addr.in.s_addr = htonl(map->last_ip);

    member = members;
    for (id = 0; id < map->elements; id++) {
        if (test_bit(id, map->members)) {
            member->addr.in.s_addr = htonl(map->first_ip + id);
            if (set->comment) {
                ext = get_elem(map->extensions, id, set->dsize);
                rte_strlcpy(member->comment, ext->comment, IPSET_MAXCOMLEN);
            }
            member++;
        }
    }
}

static int
bitmap_ip_adt(int opcode, struct ipset *set, struct ipset_param *param)
{
    int ret;
    elem_t e;
    ext_t *ext;
    uint32_t ip = 0, ip_to = 0;
    struct bitmap_ip *map = set->data;
    ipset_adtfn adtfn = set->type->adtfn[opcode];

    ip = ntohl(param->range.min_addr.in.s_addr);

    if (opcode == IPSET_OP_TEST) {
        e.id = ip_to_id(map, ip);
        return adtfn(set, &e, 0);
    }

    if (param->cidr) {
        ip_set_mask_from_to(ip, ip_to, param->cidr);
    } else {
        ip_to = ntohl(param->range.max_addr.in.s_addr);
    }
    for (; ip <= ip_to; ip++) {
        if (ip < map->first_ip || ip > map->last_ip)
            continue;
        e.id = ip_to_id(map, ip);
        ret = adtfn(set, &e, param->flag);

        if (ret)
            return ret;

        if (set->comment && opcode == IPSET_OP_ADD) {
            ext = get_elem(map->extensions, e.id, set->dsize);
            rte_strlcpy(ext->comment, param->comment, IPSET_MAXCOMLEN);
        }
    }
    return EDPVS_OK;
}

static int
bitmap_ip_test(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
{
    elem_t e;
    struct rte_ipv4_hdr *ip4hdr;
    struct bitmap_ip *map = set->data;

    if (set->family != AF_INET || mbuf_address_family(mbuf) != AF_INET)
        return 0;

    ip4hdr = mbuf_header_l3(mbuf);
    if (unlikely(!ip4hdr))
        return 0;

    memset(&e, 0, sizeof(e));

    if (dst_match)
        e.id = ip_to_id(map, ntohl(ip4hdr->dst_addr));
    else
        e.id = ip_to_id(map, ntohl(ip4hdr->src_addr));

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant bitmap_ip_variant = {
    .adt = bitmap_ip_adt,
    .test = bitmap_ip_test,
    .bitmap.do_del = bitmap_ip_do_del,
    .bitmap.do_test = bitmap_ip_do_test,
    .bitmap.do_list = bitmap_ip_do_list
};

static int
bitmap_ip_create(struct ipset *set, struct ipset_param *param)
{
    void *mem;
    size_t size, map_size;
    uint32_t elements;
    struct bitmap_ip *map;
    uint32_t first_ip = 0, last_ip = 0;
    struct inet_addr_range *range = &param->range;

    first_ip = ntohl(range->min_addr.in.s_addr);
    if (param->cidr) {
        ip_set_mask_from_to(first_ip, last_ip, param->cidr);
    } else {
        last_ip = ntohl(param->range.max_addr.in.s_addr);
    }

    elements = last_ip - first_ip + 1;
    set->comment = param->option.create.comment? true : false;
    set->dsize = set->comment? sizeof(ext_t) : 0;
    set->variant = &bitmap_ip_variant;

    /* allocate memory */
    size = sizeof(*map);
    map_size = BITS_TO_LONGS(elements) * sizeof(unsigned long);
    size += map_size;
    size += elements * set->dsize;

    mem = rte_zmalloc("ipset bitmap:ip", size, RTE_CACHE_LINE_SIZE);
    if (unlikely(mem == NULL))
        return EDPVS_NOMEM;
    /* memory layout :
      | map | members | extensions | */
    map = mem;
    map->size = size;
    map->elements = elements; 
    map->members = mem + sizeof(*map);
    map->extensions = mem + sizeof(*map) + map_size;

    map->first_ip = first_ip;
    map->last_ip = last_ip;
    map->cidr = param->cidr;
    set->data = mem;

    return EDPVS_OK;
}

struct ipset_type bitmap_ip_type = {
    .name       = "bitmap:ip",
    .create     = bitmap_ip_create,
    .destroy    = bitmap_destroy,
    .flush      = bitmap_flush,
    .list       = bitmap_list,
    .adtfn      = bitmap_adtfn
};
