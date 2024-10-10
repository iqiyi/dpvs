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
#include "ipset/ipset_bitmap.h"

#define do(adt, ...) set->variant->bitmap.do_##adt(__VA_ARGS__)

static int
bitmap_add(struct ipset *set, void *value, uint16_t flag)
{
    struct bitmap_map *map = set->data;
    struct bitmap_elem *e = value;
    int ret = do(test, value, map, set->dsize);

    if (e->id >= map->elements)
        return EDPVS_INVAL;

    /* To avoid same IP, different MAC or other elements */
    if (ret || test_bit(e->id, map->members)) {
        if (flag & IPSET_F_FORCE)
            return EDPVS_OK;
        return EDPVS_EXIST;
    }

    set_bit(e->id, map->members);
    set->elements++;
    return EDPVS_OK;
}

static int
bitmap_del(struct ipset *set, void *value, uint16_t flag)
{
    struct bitmap_map *map = set->data;
    struct bitmap_elem *e = value;

    if (e->id >= map->elements)
        return EDPVS_INVAL;

    if (!do(del, value, map)) {
        if (flag & IPSET_F_FORCE)
            return EDPVS_OK;
        return EDPVS_NOTEXIST;
    }

    set->elements--;
    return EDPVS_OK;
}

static int
bitmap_test(struct ipset *set, void *value, uint16_t flag)
{
    struct bitmap_map *map = set->data;
    struct bitmap_elem *e = value;

    if (e->id >= map->elements)
        return 0;

    return do(test, value, map, set->dsize);
}

ipset_adtfn bitmap_adtfn[IPSET_ADT_MAX] = {
    [ IPSET_OP_ADD ] = bitmap_add,
    [ IPSET_OP_DEL ] = bitmap_del,
    [ IPSET_OP_TEST ] = bitmap_test
};

void
bitmap_flush(struct ipset *set)
{
    struct bitmap_map *map = set->data;

    bitmap_zero(map->members, map->elements);
    set->elements = 0;
}

void
bitmap_destroy(struct ipset *set)
{
    rte_free(set->data);
}

void
bitmap_list(struct ipset *set, struct ipset_info *info)
{
    struct bitmap_map *map = set->data;

    strcpy(info->name, set->name);
    strcpy(info->type, set->type->name);
    info->comment = set->comment? true : false;
    info->af = AF_INET;
    info->entries = set->elements;
    info->size = map->size;

    do(list, set, &info->bitmap, info->members);
}
