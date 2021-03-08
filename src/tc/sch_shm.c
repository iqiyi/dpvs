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

/*
 * Qsch private data (global data) that's shared by all workers.
 *
 * Wenchao Yu <yunwenchao@qiyi.com>, Mar. 2021, initial.
 */
#include <rte_spinlock.h>
#include "netif.h"
#include "tc/sch.h"
#include "list.h"

#define SCH_SHM_TABLE_BITS      8
#define SCH_SHM_TABLE_SIZE      (1 << SCH_SHM_TABLE_BITS)
#define SCH_SHM_TALBE_MASK      ((SCH_SHM_TABLE_SIZE) - 1)

struct sch_shm_obj {
    struct list_head list;
    portid_t    portid;
    tc_handle_t handle;
    uint32_t    refcnt;
    uint32_t    len;
    char        data[0];
};

struct shm_hash_node {
    struct list_head bucket;
    rte_spinlock_t lock;
};

struct shm_hash_node *sch_shm_table;

static inline int sch_shm_hash(portid_t pid, tc_handle_t handle)
{
    return (((uint16_t)pid + 419) ^ ((uint16_t)(TC_H_MAJ(handle) >> 16)) ^ ((uint16_t)TC_H_MIN(handle))) & SCH_SHM_TALBE_MASK;
}

static struct sch_shm_obj* __sch_shm_lookup(portid_t pid, tc_handle_t handle)
{
    struct sch_shm_obj *obj;
    int hash = sch_shm_hash(pid, handle);

    list_for_each_entry(obj, &sch_shm_table[hash].bucket, list) {
        if (obj->portid == pid && obj->handle == handle)
            return obj;
    }

    return NULL;
}

void *qsch_shm_get_or_create(struct Qsch *sch, uint32_t len)
{
    struct sch_shm_obj *obj = NULL;
    portid_t pid = sch->tc->dev->id;
    tc_handle_t handle = sch->handle;
    int hash = sch_shm_hash(pid, handle);

    rte_spinlock_lock(&sch_shm_table[hash].lock);
    obj = __sch_shm_lookup(pid, handle);
    if (obj) {
        assert(obj->len == len);
        obj->refcnt++;
        goto done;
    }
    
    obj = rte_zmalloc("qsch_shm_obj", sizeof(struct sch_shm_obj) + len, RTE_CACHE_LINE_SIZE);
    if (!obj)
        goto done;
    
    obj->portid = pid;
    obj->handle = handle;
    obj->len = len;
    obj->refcnt = 1;

    list_add_tail(&obj->list, &sch_shm_table[hash].bucket);

done:
    rte_spinlock_unlock(&sch_shm_table[hash].lock);
    if (obj)
        return (void *)obj->data;
    return NULL;
}

int qsch_shm_put_or_destroy(struct Qsch *sch)
{
    int err = EDPVS_OK;
    struct sch_shm_obj *obj = NULL;
    portid_t pid = sch->tc->dev->id;
    tc_handle_t handle = sch->handle;
    int hash = sch_shm_hash(pid, handle);

    rte_spinlock_lock(&sch_shm_table[hash].lock);
    obj = __sch_shm_lookup(pid, handle);
    if (!obj) {
        err = EDPVS_NOTEXIST;
        goto done;
    }

    if (--obj->refcnt == 0) {
        list_del(&obj->list);
        rte_free(obj);
    }

done:
    rte_spinlock_unlock(&sch_shm_table[hash].lock);
    return err;
}

int qsch_shm_init(void)
{
    int i;

    sch_shm_table = rte_zmalloc("sch_shm_table",
            SCH_SHM_TABLE_SIZE * sizeof(struct shm_hash_node), RTE_CACHE_LINE_SIZE);
    if (!sch_shm_table)
        return EDPVS_NOMEM;

    for (i = 0; i < SCH_SHM_TABLE_SIZE; i++) {
        INIT_LIST_HEAD(&sch_shm_table[i].bucket);
        rte_spinlock_init(&sch_shm_table[i].lock);
    }
    return EDPVS_OK;
}

int qsch_shm_term(void)
{
    int i;
    struct sch_shm_obj *obj, *next;

    for (i = 0; i < SCH_SHM_TABLE_SIZE; i++) {
        rte_spinlock_lock(&sch_shm_table[i].lock);
        list_for_each_entry_safe(obj, next, &sch_shm_table[i].bucket, list) {
            if (--obj->refcnt == 0) {
                list_del(&obj->list);
                rte_free(obj);
            }
            // FIXME: free the obj whose refcnt != 0
        }
        rte_spinlock_unlock(&sch_shm_table[i].lock);
    }

    rte_free(sch_shm_table);

    return EDPVS_OK;
}
