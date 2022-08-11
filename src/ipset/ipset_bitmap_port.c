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

struct bitmap_port {
    size_t size;                /* total size */
    uint32_t elements;          /* number of max elements in the set */
    unsigned long *members;     /* the set members */
    unsigned char *extensions;  /* the extensions for each member */

    uint16_t first_port;        /* host byte order, included in range */
    uint16_t last_port;         /* host byte order, included in range */
};

typedef struct bitmap_elem elem_t;

typedef struct bitmap_port_ext {
    char comment[IPSET_MAXCOMLEN];
} ext_t;

/* port layout
    | TCP 1st-last | UDP 1st-last |
 */
static uint32_t
port_to_id(struct bitmap_port *m, uint16_t port, uint8_t proto)
{
    if (proto == IPPROTO_TCP)
        return port - m->first_port;
    else
        return port - m->first_port + m->elements/2;
}

static int
bitmap_port_do_del(struct bitmap_elem *e, struct bitmap_map *map)
{
    return test_and_clear_bit(e->id, map->members);
}

static int
bitmap_port_do_test(struct bitmap_elem *e, struct bitmap_map *map, size_t dsize)
{
    return test_bit(e->id, map->members);
}

static void
bitmap_port_do_list(struct ipset *set, struct ipset_bitmap_header *header,
                struct ipset_member *members)
{
    struct bitmap_port *map = set->data;
    struct ipset_member *member;
    int id;
    ext_t *ext;

    header->range.min_port = map->first_port;
    header->range.max_port = map->last_port;

    member = members;
    for (id = 0; id < map->elements; id++) {
        if (test_bit(id, map->members)) {
            if (id >= map->elements/2) {
                member->port = map->first_port + id - map->elements/2;
                member->proto = IPPROTO_UDP;
            } else {
                member->port = map->first_port + id;
                member->proto = IPPROTO_TCP;
            }
            if (set->comment) {
                ext = get_elem(map->extensions, id, set->dsize);
                rte_strlcpy(member->comment, ext->comment, IPSET_MAXCOMLEN);
            }
            member++;
        }
    }
}

static int
bitmap_port_adt(int opcode, struct ipset *set, struct ipset_param *param)
{
    int ret;
    elem_t e;
    ext_t *ext;
    uint16_t port, port_from, port_to;
    struct bitmap_port *map = set->data;
    ipset_adtfn adtfn = set->type->adtfn[opcode];

    port_from = param->range.min_port;
    port_to = param->range.max_port;

    if (opcode == IPSET_OP_TEST) {
        e.id = port_to_id(map, port_from, param->proto);
        return adtfn(set, &e, 0);
    }

    for (port = port_from; port >= port_from && port <= port_to; port++) {
        if (port < map->first_port || port > map->last_port)
            continue;
        e.id = port_to_id(map, port, param->proto);
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
bitmap_port_test(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
{
    elem_t e;
    uint16_t proto;
    struct rte_udp_hdr *l4hdr;
    struct bitmap_port *map = set->data;

    proto = mbuf_protocol(mbuf);
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return 0;
    l4hdr = mbuf_header_l4(mbuf);
    if (!l4hdr)
        return 0;

    memset(&e, 0, sizeof(e));

    if (dst_match)
        e.id = port_to_id(map, ntohs(l4hdr->dst_port), proto);
    else
        e.id = port_to_id(map, ntohs(l4hdr->src_port), proto);

    return set->type->adtfn[IPSET_OP_TEST](set, &e, 0);
}

struct ipset_type_variant bitmap_port_variant = {
    .adt = bitmap_port_adt,
    .test = bitmap_port_test,
    .bitmap.do_del = bitmap_port_do_del,
    .bitmap.do_test = bitmap_port_do_test,
    .bitmap.do_list = bitmap_port_do_list
};

static int
bitmap_port_create(struct ipset *set, struct ipset_param *param)
{
    void *mem;
    size_t size, map_size;
    uint32_t elements;
    struct bitmap_port *map;
    uint16_t first_port = 0, last_port = 0;
    struct inet_addr_range *range = &param->range;

    first_port = range->min_port;
    last_port = range->max_port;

    /* TCP and UDP both included */
    elements = (last_port - first_port + 1) * 2;
    set->comment = param->option.create.comment? true : false;
    set->dsize = set->comment? sizeof(ext_t) : 0;
    set->variant = &bitmap_port_variant;

    /* allocate memory */
    size = sizeof(*map);
    map_size = BITS_TO_LONGS(elements) * sizeof(unsigned long);
    size += map_size;
    size += elements * set->dsize;

    mem = rte_zmalloc("ipset bitmap:port", size, RTE_CACHE_LINE_SIZE);
    if (unlikely(mem == NULL))
        return EDPVS_NOMEM;
    /* memory layout :
      | map | members | extensions | */
    map = mem;
    map->size = size;
    map->elements = elements; 
    map->members = mem + sizeof(*map);
    map->extensions = mem + sizeof(*map) + map_size;

    map->first_port = first_port;
    map->last_port = last_port;
    set->data = mem;

    return EDPVS_OK;
}

struct ipset_type bitmap_port_type = {
    .name       = "bitmap:port",
    .create     = bitmap_port_create,
    .destroy    = bitmap_destroy,
    .flush      = bitmap_flush,
    .list       = bitmap_list,
    .adtfn      = bitmap_adtfn
};
