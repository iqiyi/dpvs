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
#include "conf/common.h"
#include "ipset/ipset_hash.h"
#include "ipset/pfxlen.h"
#include "parser/parser.h"

#define DEF_HASHSIZE    1024
#define DEF_MAXELEM     65535

#define do(act, ...) set->variant->hash.do_##act(__VA_ARGS__)

/* hash mempool */
#define IPSET_HASH_POOL_SIZE_MIN    65536
#define IPSET_HASH_POOL_SIZE_DEF    262143
#define IPSET_HASH_CACHE_SIZE_DEF   256
/* this should be larger than the element of all types */
#define HASH_ELEM_SIZE_MAX          128
#define this_hash_cache             (ipset_hash_cache[rte_socket_id()])

static struct rte_mempool *ipset_hash_cache[DPVS_MAX_SOCKET];

static int ipset_hash_pool_size = IPSET_HASH_POOL_SIZE_DEF;

/* common hash element difinition 
  (hash type that contains net element must follow the order) */
typedef struct hash_elem {
    union inet_addr ip1;
    uint8_t cidr;
    union inet_addr ip2;
    uint8_t cidr2;
} elem_t;

void
hash_data_netmask4(void *elem, uint8_t cidr, bool inner)
{
    elem_t *e = (elem_t *)elem;

    if (inner) {
        e->ip2.in.s_addr &= ip_set_netmask(cidr);
        e->cidr2 = cidr;
    } else {
        e->ip1.in.s_addr &= ip_set_netmask(cidr);
        e->cidr = cidr;
    }
}

void
hash_data_netmask6(void *elem, uint8_t cidr, bool inner)
{
    elem_t *e = (elem_t *)elem;

    if (inner) {
        ip6_netmask(&e->ip2, cidr);
        e->cidr2 = cidr;
    } else {
        ip6_netmask(&e->ip1, cidr);
        e->cidr = cidr;
    }
}

uint32_t
jhash_hashkey(void *data, int len, uint32_t mask)
{
    return rte_jhash(data, len, 0) & mask;
}

static int
hash_add(struct ipset *set, void *value, uint16_t flag)
{
    struct hash_type *htype = set->data;
    struct hash_entry *hnode;
    struct list_head *head;
    void *obj, *elem;
    uint32_t key;
    elem_t *e;

    if (unlikely(set->elements >= htype->maxelem))
        return EDPVS_NOMEM;

    key = do(hash, value, set->hash_len, htype->mask);
    head = &htype->htable[key];
    list_for_each_entry(hnode, head, list) {
        if (do(compare, value, hnode->elem) != COMPARE_INEQUAL) {
            if (!flag & IPSET_F_FORCE)
                return EDPVS_EXIST;
            //overwrite extension
            rte_memcpy(hnode->elem + set->hash_len,
                    value + set->hash_len, set->dsize - set->hash_len);
            return EDPVS_OK;
        }
    }

    /* obj memory layout
       | hnode | elem | */
    rte_mempool_get(this_hash_cache, &obj); 
    if (unlikely(!obj))
        return EDPVS_NOMEM;

    memset(obj, 0,  sizeof(struct hash_entry) +
            HASH_ELEM_SIZE_MAX);

    hnode = (struct hash_entry *)obj;
    list_add_tail(&hnode->list, head);

    elem = obj + sizeof(*hnode);
    rte_memcpy(elem, value, set->dsize);
    hnode->elem = elem;
    set->elements++;

    /* update cidr map */
    e = (elem_t *)value;
    if (set->net_count > 0)
        htype->cidr_map[e->cidr][0]++;
    if (set->net_count == 2)
        htype->cidr_map[e->cidr2][1]++;

    return EDPVS_OK;
}

static int
hash_del(struct ipset *set, void *value, uint16_t flag)
{
    struct hash_type *htype = set->data;
    struct hash_entry *hnode, *next;
    struct list_head *head;
    uint32_t key;
    elem_t *e;

    key = do(hash, value, set->hash_len, htype->mask);
    head = &htype->htable[key];
    list_for_each_entry_safe(hnode, next, head, list) {
        if (do(compare, value, hnode->elem) != COMPARE_INEQUAL) {
            list_del(&hnode->list);
            rte_mempool_put(this_hash_cache, hnode);
            set->elements--;

            /* update cidr map */
            e = (elem_t *)value;
            if (set->net_count > 0)
                htype->cidr_map[e->cidr][0]--;
            if (set->net_count == 2)
                htype->cidr_map[e->cidr2][1]--;

            return EDPVS_OK;
        }
    }
    if (flag & IPSET_F_FORCE)
        return EDPVS_OK;
    return EDPVS_NOTEXIST;
}

static inline int
do_test(struct ipset *set, struct hash_type *htype, void *elem)
{
    int res;
    uint32_t key;
    struct hash_entry *hnode;
    struct list_head *head ;

    key = do(hash, elem, set->hash_len, htype->mask);
    head = &htype->htable[key];
    list_for_each_entry(hnode, head, list) {
        res = do(compare, elem, hnode->elem);
        if (res == COMPARE_EQUAL_ACCEPT ||
                res == COMPARE_EQUAL_REJECT)
            return res;
    }
    return COMPARE_INEQUAL;
}

static int
test_cidrs(struct ipset *set, struct hash_type *htype, void *value)
{
    int i, j, res;
    uint8_t host_mask = set->family == AF_INET? 32 : 128;

    if (set->net_count == 1) {
        for (i = host_mask; i >= 0; i--) {
            if (htype->cidr_map[i][0] <= 0)
                continue;
            do(netmask, value, i, false);

            res = do_test(set, htype, value);
            if (res == COMPARE_EQUAL_ACCEPT)
                return 1;
            if (res == COMPARE_EQUAL_REJECT) // nomatch
                return 0;
        }
        return 0;
    } else {
        elem_t *e = (elem_t *)value;
        union inet_addr ip2_save = e->ip2;
        for (i = host_mask; i >= 0; i--) {
            e->ip2 = ip2_save;
            if (htype->cidr_map[i][0] <= 0)
                continue;
            do(netmask, value, i, false);
            for (j = host_mask; j >= 0; j--) {
                if (htype->cidr_map[j][1] <= 0)
                    continue;
                do(netmask, value, j, true);

                res = do_test(set, htype, value);
                if (res == COMPARE_EQUAL_ACCEPT)
                    return 1;
                if (res == COMPARE_EQUAL_REJECT) // nomatch
                    return 0;
            }
        }
        return 0;
    }
}

static int
hash_test(struct ipset *set, void *value, uint16_t flag)
{
    struct hash_type *htype = set->data;
    elem_t *e = (elem_t *)value;
    /* If we test an IP address and not a network cidr,
     * try all possible network sizes
     */
    if ((set->net_count == 1 && !e->cidr) ||
        (set->net_count == 2 && !(e->cidr || e->cidr2))) {

        return test_cidrs(set, htype, value);
    }

    if (do_test(set, htype, value) == COMPARE_EQUAL_ACCEPT)
        return 1;

    return 0;
}

ipset_adtfn hash_adtfn[IPSET_ADT_MAX] = {
    [ IPSET_OP_ADD ] = hash_add,
    [ IPSET_OP_DEL ] = hash_del,
    [ IPSET_OP_TEST ] = hash_test
};

void
hash_flush(struct ipset *set)
{
    int i;
    struct hash_type *htype = set->data;
    struct hash_entry *hnode, *next;

    for (i = 0; i < htype->hashsize; i++) {
        list_for_each_entry_safe(hnode, next, &htype->htable[i], list) {
            list_del(&hnode->list);
            rte_mempool_put(this_hash_cache, hnode);
            set->elements--;
        }
    }

    assert(set->elements == 0);
    memset(htype->cidr_map, 0, sizeof(htype->cidr_map));
}

void
hash_destroy(struct ipset *set)
{
    hash_flush(set);
    rte_free(set->data);
}

void
hash_list(struct ipset *set, struct ipset_info *info)
{
    int i;
    struct hash_type *htype = set->data;
    struct hash_entry *hnode;
    struct ipset_member *member = info->members;

    strcpy(info->name, set->name);
    strcpy(info->type, set->type->name);
    info->comment = set->comment? true : false;
    info->af = set->family;
    info->entries = set->elements;
    info->size = htype->hashsize * sizeof(struct list_head) +
        (sizeof(struct hash_entry) + HASH_ELEM_SIZE_MAX) * set->elements;

    info->hash.hashsize = htype->hashsize;
    info->hash.maxelem = htype->maxelem;

    for (i = 0; i < htype->hashsize; i++) {
        list_for_each_entry(hnode, &htype->htable[i], list) {
            do(list, member, hnode->elem, set->comment);
            member++;
        }
    }
}

/* common create func for hash type */
int
hash_create(struct ipset *set, struct ipset_param *param)
{
    int i;
    void *mem;
    size_t size;
    uint32_t hashsize;
    struct hash_type *htype;
    struct ipset_option *opt = &param->option;

    if (opt->create.hashsize) {
        is_power2(opt->create.hashsize, 0, &opt->create.hashsize);
        hashsize = opt->create.hashsize;
    } else {
        hashsize = DEF_HASHSIZE;
    }

    /* allocate memory */
    size = sizeof(*htype) + hashsize * sizeof(struct list_head);
    mem = rte_zmalloc("ipset hashtype", size, RTE_CACHE_LINE_SIZE);
    if (unlikely(mem == NULL))
        return EDPVS_NOMEM;
    /* memroy layout:
       | htype | htable | */
    htype = mem;
    htype->htable = mem + sizeof(*htype);

    htype->hashsize = hashsize;
    htype->mask = htype->hashsize - 1;

    if (opt->create.maxelem)
        htype->maxelem = opt->create.maxelem;
    else
        htype->maxelem = DEF_MAXELEM;

    for (i = 0; i < htype->hashsize; i++)
        INIT_LIST_HEAD(&htype->htable[i]);

    set->data = mem;

    return EDPVS_OK;
}

int 
ipset_hash_init(void)
{
    int i;
    char poolname[32];

    for (i = 0; i < get_numa_nodes(); i++) {
        snprintf(poolname, sizeof(poolname), "ipset_hash_pool_%d", i);
        ipset_hash_cache[i] = rte_mempool_create(poolname,
                            IPSET_HASH_POOL_SIZE_DEF,
                            sizeof(struct hash_entry) + HASH_ELEM_SIZE_MAX,
                            IPSET_HASH_CACHE_SIZE_DEF,
                            0, NULL, NULL, NULL, NULL, i, 0);
        if (!ipset_hash_cache[i]) {
            return EDPVS_NOMEM;
        }
    }
    return EDPVS_OK;
}

static void 
ipset_hash_pool_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int pool_size;

    assert(str);

    pool_size = atoi(str);

    if (pool_size < IPSET_HASH_POOL_SIZE_MIN) {
        RTE_LOG(WARNING, IPSET, "invalid ipset_hash_pool_size %s, using default %d\n",
                str, IPSET_HASH_POOL_SIZE_DEF);
        ipset_hash_pool_size = IPSET_HASH_POOL_SIZE_DEF;
    } else {
        is_power2(pool_size, 1, &pool_size);
        RTE_LOG(INFO, IPSET, "ipset_hash_pool_size = %d (round to 2^n-1)\n", pool_size);
        ipset_hash_pool_size = pool_size - 1;
    }

    FREE_PTR(str);
}

void 
install_ipset_hash_keywords(void)
{
    install_keyword_root("ipset_defs", NULL);
    install_keyword("ipset_hash_pool_size", ipset_hash_pool_size_handler, KW_TYPE_INIT);
}
