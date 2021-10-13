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
#ifndef __DPVS_IPSET_BITMAP_H__
#define __DPVS_IPSET_BITMAP_H__

#include <stdint.h>
#include <stddef.h>
#include "ipset.h"

#define get_elem(extensions, id, dsize)     \
        (void *)(extensions + (id) * (dsize))

/* each bitmap type should follow this order */
struct bitmap_map {
    size_t size;
    uint32_t elements;
    unsigned long *members;
    unsigned char *extensions;
};

/* common bitmap elemnt difinition */
struct bitmap_elem {
    uint32_t id;
};

extern ipset_adtfn bitmap_adtfn[IPSET_ADT_MAX];

void bitmap_flush(struct ipset *set);
void bitmap_destroy(struct ipset *set);
void bitmap_list(struct ipset *set, struct ipset_info *data);

#endif
