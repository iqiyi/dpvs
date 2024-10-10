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
#ifndef __DPVS_IPSET_H__
#define __DPVS_IPSET_H__

#include <assert.h>
#include <arpa/inet.h>
#include "list.h"
#include "netif.h"
#include "dpdk.h"
#include "conf/common.h"
#include "conf/ipset.h"
#include "ipvs/ipvs.h"

#define IPSET
#define RTE_LOGTYPE_IPSET       RTE_LOGTYPE_USER1

#define IPSET_ADT_MAX           IPSET_OP_MAX

struct ipset;

struct bitmap_elem;
struct bitmap_map;

/* add/del/test func prototype for ipset */
typedef int (*ipset_adtfn)(struct ipset *set, void *value, uint16_t flag);

struct ipset_type {
    struct list_head l;

    char name[IPSET_MAXNAMELEN];

    /* Create a set */
    int (*create)(struct ipset *set, struct ipset_param *param);
    /* Destroy the set */
    void (*destroy)(struct ipset *set);
    /* Flush the elements */
    void (*flush)(struct ipset *set);
    /* List elements */
    void (*list)(struct ipset *set, struct ipset_info *info);
    /* Low level test/add/del functions */
    ipset_adtfn *adtfn;
};

/* functions that are determined when the set is being created */
struct ipset_type_variant {
    /* test/add/del entries called by dpip */
    int (*adt)(int opcode, struct ipset *set, struct ipset_param *param);
    /* Internal test function */
    int (*test)(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match);
    /* Basic functions that each ipset type should implement partially */
    union {
        struct {
            int (*do_del)(struct bitmap_elem *e, struct bitmap_map *map);
            int (*do_test)(struct bitmap_elem *e, struct bitmap_map *map, size_t dsize);
            void (*do_list)(struct ipset *set, struct ipset_bitmap_header *header,
                    struct ipset_member *members);
        } bitmap;
        struct {
            /* Type that contains 'net' element must implement */
            void (*do_netmask)(void *elem, uint8_t cidr, bool inner);
            int (*do_compare)(const void *adt_elem, const void *set_elem);
            void (*do_list)(struct ipset_member *members, void *elem, bool comment);
            uint32_t (*do_hash)(void *data, int len, uint32_t mask);
        } hash;
    };
};

struct ipset {
    struct list_head list;

    char name[IPSET_MAXNAMELEN];
    struct ipset_type           *type;      // Set type
    struct ipset_type_variant   *variant;   // Type specific functions

    uint32_t elements;          // Number of elements of this set
    size_t dsize;               // Size of each element
    int hash_len;               // Length of hash data
    int family;                 // Address family
    int net_count;              // Number of net elements(<= 2)
    int references;             // Reference count
    bool comment;               // Is comment enabled
    void *data;                 // Type specific data
};

/* IPset APIs */

/*
 * Function name : ipset_get
 * Description : Get the set pointer by name
 * Parameter :
 *        @name            name of the set
 * Return : pointer to the set   - success
 *          NULL                 - fail
 */
struct ipset *ipset_get(const char *name);

/*
 * Function name : ipset_put
 * Description : Put back the set
 * Parameter :
 *        @set            pointer to the IPset
 */
static inline void
ipset_put(struct ipset *set)
{
    set->references--;
}

/*
 * Function name : elem_in_set
 * Description : Judge if element 'mbuf' is in the set
 * Parameter :
 *        @set          pointer to the IPset
 *        @mbuf         pointer to the mbuf
 *        @dst_match    true if to match dst addr/port in mbuf, otherwise false
 * Return :  1     - in set
 *           0     - NOT in set
 */
static inline int
elem_in_set(struct ipset *set, struct rte_mbuf *mbuf, bool dst_match)
{
    assert(set->variant->test);

    return set->variant->test(set, mbuf, dst_match);
}

int ipset_ctrl_init(void);
int ipset_ctrl_term(void);

int ipset_hash_init(void);

int ipset_init(void);
int ipset_term(void);

int ipset_local_action(struct ipset_param * param);
int ipset_do_list(const void *conf, void **out, size_t *outsize);

#endif
