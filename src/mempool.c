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

#include <assert.h>
#include "conf/common.h"
#include "dpdk.h"
#include "mempool.h"

#ifndef CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE
#define CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE 512
#endif
#define MP_CACHE_SIZE_MAX   CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE
#define MP_CACHE_SIZE_DEF   (MP_CACHE_SIZE_MAX / 8)


static inline int log2_lower(int num)
{
    int lg = -1;
    while (num) {
        num = (num >> 1);
        lg++;
    }
    return lg;
}

static int mp_elem_create(char *name_pref, struct dpvs_mp_elem *mp_elt, uint32_t obj_sz, uint32_t obj_num)
{
    unsigned cache_size;
    struct rte_mempool *pool;
    char name[MP_NAMSIZ];

    if (unlikely(!mp_elt))
        return EDPVS_INVAL;

    /* Cache size must be lower or equal to CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE and obj_num / 1.5. */
    cache_size = MP_CACHE_SIZE_DEF;
    if (cache_size >= obj_num * 2/3)
        cache_size = obj_num / 2;

    is_power2((int)obj_num, 1, (int *)&obj_num);
    --obj_num;

    snprintf(name, sizeof(name), "%s_s%d_n%d", name_pref, obj_sz, obj_num);
    pool = rte_mempool_create(name, obj_num, obj_sz, cache_size, 0, NULL, NULL,
            NULL, NULL, SOCKET_ID_ANY, 0);
    if (unlikely(!pool))
        return EDPVS_NOMEM;

    strncpy(mp_elt->name, name, sizeof(mp_elt->name) - 1);
    mp_elt->obj_size = obj_sz;
    mp_elt->obj_num = obj_num;
    mp_elt->cache_size = cache_size;
    mp_elt->pool = pool;

    return EDPVS_OK;
}

static void mp_elem_destroy(struct dpvs_mp_elem *mp_elt)
{
    if (unlikely(!mp_elt))
        return;
    if (mp_elt->pool)
        rte_mempool_free(mp_elt->pool);
    mp_elt->obj_num = 0;
    mp_elt->cache_size = 0;
}

struct dpvs_mempool *dpvs_mempool_create(char *name,
        int obj_size_min, int obj_size_max, int pool_mem_kbytes)
{
    int i, idx_start, idx_end, arr_size;
    uint32_t obj_size, pool_mem;
    uint32_t obj_num;
    struct dpvs_mempool *mp;

    if (rte_lcore_id() != rte_get_main_lcore()) {
        RTE_LOG(WARNING, DPVS_MPOOL, "%s could be called on master lcore only!", __func__);
        return NULL;
    }

    if (obj_size_min > obj_size_max) {
        RTE_LOG(ERR, DPVS_MPOOL, "%s: %s: invalid object size range: %d->%d\n",
                __func__, name, obj_size_min, obj_size_max);
        return NULL;
    }
    if (obj_size_min < MP_OBJ_SIZE_MIN)
        obj_size_min = MP_OBJ_SIZE_MIN;
    if (obj_size_max > MP_OBJ_SIZE_MAX)
        obj_size_max = MP_OBJ_SIZE_MAX;
    is_power2(obj_size_min, 0, &obj_size_min);
    is_power2(obj_size_max, 0, &obj_size_max);

    is_power2(pool_mem_kbytes, 0, &pool_mem_kbytes);
    pool_mem = pool_mem_kbytes * 1024;
    if (pool_mem / obj_size_max < MP_SIZE_MIN)
        pool_mem = obj_size_max * MP_SIZE_MIN;

    idx_start = log2_lower(obj_size_min);
    idx_end = log2_lower(obj_size_max);
    arr_size = idx_end - idx_start + 1;

    mp = rte_zmalloc(name, sizeof(struct dpvs_mempool) + sizeof(struct dpvs_mp_elem)
            * arr_size, RTE_CACHE_LINE_SIZE);
    if (unlikely(!mp)) {
        RTE_LOG(ERR, DPVS_MPOOL, "%s: no memory for dpvs_mempool %s!\n", __func__, name);
        return NULL;
    }

    strncpy(mp->name, name, sizeof(mp->name) - 1);
    mp->obj_size_min = obj_size_min;
    mp->obj_size_max = obj_size_max;
    mp->pool_mem = pool_mem;
    mp->pool_arr_size = arr_size;

    obj_size = obj_size_min;
    for (i = 0; i < arr_size; i++) {
        obj_num = pool_mem / obj_size;
        if (unlikely(mp_elem_create(name, &mp->pool_array[i], obj_size, obj_num) != EDPVS_OK)) {
            RTE_LOG(ERR, DPVS_MPOOL, "%s: no memory for mp_elem_create of %s_s%d_n%d!\n",
                    __func__, name, obj_size, obj_num);
            dpvs_mempool_destroy(mp);
            return NULL;
        }
        obj_size *= 2;
        RTE_LOG(INFO, DPVS_MPOOL, "elem mempool created: %s.\n", mp->pool_array[i].name);
    }

    RTE_LOG(INFO, DPVS_MPOOL, "%s: create mempool %s: obj_size %d->%d, arr_size %d, pool_mem %dKB\n",
            __func__, name, obj_size_min, obj_size_max, arr_size, pool_mem/1024);
    return mp;
}

void dpvs_mempool_destroy(struct dpvs_mempool *mp)
{
    int i;

    if (unlikely(!mp))
        return;

    if (rte_lcore_id() != rte_get_main_lcore()) {
        RTE_LOG(WARNING, DPVS_MPOOL, "%s could be called on master lcore only!", __func__);
        return;
    }

    RTE_LOG(INFO, DPVS_MPOOL, "%s: destroy mempool %s: obj_size %d->%d, arr_size %d, pool_mem %dKB\n",
            __func__, mp->name, mp->obj_size_min, mp->obj_size_max, mp->pool_arr_size, mp->pool_mem/1024);

    for (i = 0; i < mp->pool_arr_size; i++) {
        RTE_LOG(INFO, DPVS_MPOOL, "elem mempool destroyed: %s.\n", mp->pool_array[i].name);
        mp_elem_destroy(&mp->pool_array[i]);
    }

    rte_free(mp);
}

static int get_pool_array_index(const struct dpvs_mempool *mp, int size)
{
    int lower, mid, upper;
    
    lower = 0;
    upper = mp->pool_arr_size - 1;

    if (unlikely(size > mp->pool_array[upper].obj_size))
        return -1;

    while (lower < upper) {
        if (size <= mp->pool_array[lower].obj_size)
            return lower;
        mid = (lower + upper) / 2;
        if (size <= mp->pool_array[mid].obj_size)
            upper = mid;
        else
            lower = mid + 1;
    }

    return upper;
}

void *dpvs_mempool_get(struct dpvs_mempool *mp, int size)
{
    int arr_idx, alloc_size;
    void *ptr, *data;
    struct dpvs_mp_obj_cookie *cookie;
    tailer_marker_t *tailer;

    if (unlikely(!mp))
        return NULL;

    alloc_size = size + MP_OBJ_COOKIE_OFFSET + MP_OBJ_TAILER_SIZE;

    arr_idx = get_pool_array_index(mp, alloc_size);
    if (arr_idx < 0) {
#ifdef CONFIG_DPVS_MP_DEBUG
        RTE_LOG(INFO, DPVS_MPOOL, "%s: %s allocate %d bytes memory from heap!\n",
                __func__, mp->name, size);
#endif
        goto alloc_from_heap;
    }

    if (unlikely(!mp->pool_array[arr_idx].pool)) {
        RTE_LOG(ERR, DPVS_MPOOL, "%s: missing mempool for %s::pool_array[%d]\n",
                __func__, mp->name, arr_idx);
    }

    if (rte_mempool_get(mp->pool_array[arr_idx].pool, &ptr) < 0) {
#ifdef CONFIG_DPVS_MP_DEBUG
        RTE_LOG(WARNING, DPVS_MPOOL, "%s: mempool %s full, allocate %d bytes memory from heap!\n",
                __func__,  mp->pool_array[arr_idx].name, size);
#endif
        goto alloc_from_heap;
    }

    cookie = (struct dpvs_mp_obj_cookie *)ptr;
    cookie->mark = MP_OBJ_COOKIE_MARK;
    cookie->memsize = alloc_size;
    cookie->flag = MEM_OBJ_FROM_POOL;
    cookie->pool_idx = arr_idx;

    tailer = (tailer_marker_t *)(ptr + size + MP_OBJ_COOKIE_OFFSET);
    *tailer = MP_OBJ_TAILER_MARK;

    data = ptr + MP_OBJ_COOKIE_OFFSET;;
#ifdef CONFIG_DPVS_MP_DEBUG
    RTE_LOG(DEBUG, DPVS_MPOOL, "allocate %d memory from %s\n", size, mp->pool_array[arr_idx].name);
#endif
    memset(data, 0, size);
    return data;

alloc_from_heap:
    ptr = rte_zmalloc(NULL, alloc_size, RTE_CACHE_LINE_SIZE);
    if (!ptr)
        return NULL;

    cookie = (struct dpvs_mp_obj_cookie *)ptr;
    cookie->mark = MP_OBJ_COOKIE_MARK;
    cookie->memsize = alloc_size;
    cookie->flag = MEM_OBJ_FROM_HEAP;
    cookie->pool_idx = mp->pool_arr_size; // invalid pool index

    tailer = (tailer_marker_t *)(ptr + size + MP_OBJ_COOKIE_OFFSET);
    *tailer = (uint32_t)MP_OBJ_TAILER_MARK;

    data = ptr + MP_OBJ_COOKIE_OFFSET;
    assert(dpvs_mp_elem_ok(data));
    return data;
}

void dpvs_mempool_put(struct dpvs_mempool *mp, void *obj)
{
    struct dpvs_mp_obj_cookie *cookie;
    tailer_marker_t *tailer;

    if (!mp || !obj)
        return;

    cookie = (struct dpvs_mp_obj_cookie *)(obj - MP_OBJ_COOKIE_OFFSET);
    assert(cookie->mark == MP_OBJ_COOKIE_MARK);

    tailer = (tailer_marker_t *)(obj - MP_OBJ_COOKIE_OFFSET + cookie->memsize - MP_OBJ_TAILER_SIZE);
    assert(*tailer == MP_OBJ_TAILER_MARK);

    if (cookie->flag == MEM_OBJ_FROM_POOL)
        rte_mempool_put(mp->pool_array[cookie->pool_idx].pool, (void *)cookie);
    else if (cookie->flag == MEM_OBJ_FROM_HEAP)
        rte_free((void *)cookie);
    else
        RTE_LOG(ERR, DPVS_MPOOL, "%s: unkown memory object flag %d\n", __func__, cookie->flag);
}

#ifdef CONFIG_DPVS_MP_DEBUG
bool dpvs_mp_elem_ok(void *obj)
{
    struct dpvs_mp_obj_cookie *cookie;
    tailer_marker_t *tailer;

    if (!obj)
        return true;

    cookie = (struct dpvs_mp_obj_cookie *)(obj - MP_OBJ_COOKIE_OFFSET);
    tailer = (tailer_marker_t *)(obj - MP_OBJ_COOKIE_OFFSET + cookie->memsize - MP_OBJ_TAILER_SIZE);

    if (cookie->mark != MP_OBJ_COOKIE_MARK) {
        assert(0);
        return false;
    }

    if (*tailer != MP_OBJ_TAILER_MARK) {
        assert(0);
        return false;
    }

    /* apply the patch to get `rte_memmory_ok`:
     * dpdk-stable-17.11.6/enable-dpdk-eal-memory-debug.patch */
    if (cookie->flag == MEM_OBJ_FROM_HEAP)
        assert(rte_memmory_ok((void *)cookie));

    return true;
}
#else
bool dpvs_mp_elem_ok(void *obj)
{
    return true;
}
#endif
