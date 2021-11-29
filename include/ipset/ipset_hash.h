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
#ifndef __DPVS_IPSET_HASH_H__
#define __DPVS_IPSET_HASH_H__

#include <stdint.h>
#include "ipset.h"
#include "linux_ipv6.h"

/* return value for hash.do_compare */
enum HASH_COMPARE_RESULT {
    COMPARE_INEQUAL = 0,
    COMPARE_EQUAL_ACCEPT,
    COMPARE_EQUAL_REJECT,
};

struct hash_type {
    struct list_head *htable;   /* the hash table */
    uint32_t hashsize;          /* size of the hash table */
    uint32_t mask;              /* mask of the hash size */
    uint32_t maxelem;           /* max elements in the hash */
    uint32_t initval;           /* random jhash init value */
    uint32_t cidr_map[129][2];  /* cidr map */
};

struct hash_entry {
    struct list_head list;  /* list node */

    void *elem;             /* type specific data */
};

extern ipset_adtfn hash_adtfn[IPSET_ADT_MAX];

void install_ipset_hash_keywords(void);

/* common hash type functions */
int hash_create(struct ipset *set, struct ipset_param *param);
void hash_flush(struct ipset *set);
void hash_destroy(struct ipset *set);
void hash_list(struct ipset *set, struct ipset_info *info);

void hash_data_netmask4(void *elem, uint8_t cidr, bool inner);
void hash_data_netmask6(void *elem, uint8_t cidr, bool inner);
uint32_t jhash_hashkey(void *data, int len, uint32_t mask);

static inline int hash_proto_support(uint16_t proto)
{
    return proto == IPPROTO_TCP ||
        proto == IPPROTO_UDP ||
        proto == IPPROTO_ICMP ||
        proto == IPPROTO_ICMPV6;
}

#endif
