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

#include <rte_mempool.h>
#include <rte_errno.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>
#include <rte_tailq.h>
#include "conf/eal_mem.h"
#include "eal_mem.h"
#include "ctrl.h"

#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 0, 0)
#define MAX_SEGMENT_NUM         (512)
static uint64_t s_all_socket_heap_freesz[RTE_MAX_NUMA_NODES];
#else
#define MAX_SEGMENT_NUM         RTE_MAX_MEMSEG
#endif
#define MAX_MEMZONE_NUM         RTE_MAX_MEMZONE

#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 0, 0)
static int dp_vs_get_all_socket_heap_freesz_stats(void)
{
    int i;
    struct rte_malloc_socket_stats socket_stats;

    for (i = 0; i < RTE_MAX_NUMA_NODES; i++) {
        s_all_socket_heap_freesz[i] = 0;
        if (rte_malloc_get_socket_stats(i, &socket_stats) != 0) {
            break;
        }
        s_all_socket_heap_freesz[i] = socket_stats.heap_freesz_bytes;
    }
    return 0;
}

static int dp_vs_fill_mem_seg_info(const struct rte_memseg_list *msl, const struct rte_memseg *ms,
            void *arg)
{
    eal_all_mem_seg_ret_t *eal_mem_segs = (eal_all_mem_seg_ret_t *)arg;
    eal_mem_seg_ret_t *seg_ret = NULL;

    if (MAX_SEGMENT_NUM == eal_mem_segs->seg_num) {
        return 0;
    }
    seg_ret = &eal_mem_segs->seg_info[eal_mem_segs->seg_num];
    eal_mem_segs->seg_num++;

    seg_ret->iova = ms->iova;
    seg_ret->virt_addr = ms->addr_64;
    seg_ret->len = ms->len;
    seg_ret->hugepage_sz = ms->hugepage_sz;
    seg_ret->socket_id = ms->socket_id;
    seg_ret->nchannel = ms->nchannel;
    seg_ret->nrank = ms->nrank;
    seg_ret->free_seg_len = s_all_socket_heap_freesz[ms->socket_id];

    return 0;
}

static void dp_vs_fill_mem_zone_info(const struct rte_memzone *mz, void *arg)
{
    eal_all_mem_zone_ret_t *eal_mem_zones = (eal_all_mem_zone_ret_t *)arg;
    eal_mem_zone_ret_t *zone_ret = NULL;

    if (MAX_MEMZONE_NUM == eal_mem_zones->zone_num) {
        return;
    }
    zone_ret = &eal_mem_zones->zone_info[eal_mem_zones->zone_num];
    eal_mem_zones->zone_num++;

    memcpy(zone_ret->name, mz->name, EAL_MEM_NAME_LEN);
    zone_ret->iova = mz->iova;
    zone_ret->virt_addr = mz->addr_64;
    zone_ret->len = mz->len;
    zone_ret->hugepage_sz = mz->hugepage_sz;
    zone_ret->socket_id = mz->socket_id;
}
#else
static uint64_t eal_get_free_seg_len(int socket_id)
{
    uint64_t len = 0;
    struct rte_malloc_socket_stats socket_stats;

    if (socket_id < 0 || socket_id > RTE_MAX_NUMA_NODES)
        return 0;

    memset(&socket_stats, 0, sizeof(struct rte_malloc_socket_stats));
    if (rte_malloc_get_socket_stats(socket_id, &socket_stats) != 0)
        return 0;
    len = socket_stats.heap_freesz_bytes;

    return len;
}
#endif

static int dp_vs_get_eal_mem_seg(eal_all_mem_seg_ret_t *eal_mem_segs)
{
#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 0, 0)
    dp_vs_get_all_socket_heap_freesz_stats();
    rte_memseg_walk(dp_vs_fill_mem_seg_info, eal_mem_segs);
#else
    const struct rte_mem_config *mcfg;
    eal_mem_seg_ret_t *seg_ret;
    unsigned i = 0;

    /* get pointer to global configuration */
    mcfg = rte_eal_get_configuration()->mem_config;

    for (i = 0; i < MAX_SEGMENT_NUM; i++) {
        if (NULL == mcfg->memseg[i].addr) {
            break;
        }
        seg_ret = &eal_mem_segs->seg_info[eal_mem_segs->seg_num];
        eal_mem_segs->seg_num++;
        seg_ret->iova = mcfg->memseg[i].iova;
        seg_ret->virt_addr = mcfg->memseg[i].addr_64;
        seg_ret->len = mcfg->memseg[i].len;
        seg_ret->hugepage_sz = mcfg->memseg[i].hugepage_sz;
        seg_ret->socket_id = mcfg->memseg[i].socket_id;
        seg_ret->nchannel = mcfg->memseg[i].nchannel;
        seg_ret->nrank = mcfg->memseg[i].nrank;
        seg_ret->free_seg_len = eal_get_free_seg_len(mcfg->memseg[i].socket_id);
    }
#endif

   return 0;
}

static int dp_vs_get_eal_mem_zone(eal_all_mem_zone_ret_t *eal_mem_zones)
{

#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 0, 0)
    rte_memzone_walk(dp_vs_fill_mem_zone_info, eal_mem_zones);
#else
    eal_mem_zone_ret_t *zone_ret;
    struct rte_mem_config *mcfg;
    struct rte_memzone* mz;
    unsigned i = 0;

    /* get pointer to global configuration */
    mcfg = rte_eal_get_configuration()->mem_config;

    rte_rwlock_read_lock(&mcfg->mlock);
    for (i = 0; i < MAX_MEMZONE_NUM; i++) {
        mz = &mcfg->memzone[i];
        if (NULL == mz->addr) {
            break;
        }
        zone_ret = &eal_mem_zones->zone_info[eal_mem_zones->zone_num];
        eal_mem_zones->zone_num++;
        memcpy(zone_ret->name, mz->name, EAL_MEM_NAME_LEN);
        zone_ret->phys_addr = mz->phys_addr;
        zone_ret->virt_addr = mz->addr_64;
        zone_ret->len = mz->len;
        zone_ret->hugepage_sz = mz->hugepage_sz;
        zone_ret->socket_id = mz->socket_id;
    }
    rte_rwlock_read_unlock(&mcfg->mlock);
#endif

    return 0;
}

static int dp_vs_get_eal_mem_pool(eal_all_mem_pool_ret_t *eal_mem_pools)
{
    TAILQ_HEAD(rte_mempool_list, rte_tailq_entry);
    eal_mem_pool_ret_t *mempool_ret;
    const struct rte_mempool *mp = NULL;
    struct rte_tailq_entry *te;
    struct rte_mempool_list *mempool_list;

    mempool_list = RTE_TAILQ_LOOKUP("RTE_MEMPOOL", rte_mempool_list);
    if (NULL == mempool_list)
        return -1;

    rte_mcfg_mempool_read_lock();
    eal_mem_pools->mempool_num = 0;
    TAILQ_FOREACH(te, mempool_list, next) {
        mp = (struct rte_mempool *) te->data;
        mempool_ret = &eal_mem_pools->mempool_info[eal_mem_pools->mempool_num];
        eal_mem_pools->mempool_num++;
        memcpy(mempool_ret->name, mp->name, EAL_MEM_NAME_LEN);
        mempool_ret->flags = mp->flags;
        mempool_ret->size = mp->size;
        mempool_ret->count = rte_mempool_ops_get_count(mp);
        mempool_ret->elt_size = mp->elt_size;
        mempool_ret->header_size = mp->header_size;
        mempool_ret->trailer_size = mp->trailer_size;
        mempool_ret->private_data_size = mp->private_data_size;
    }
    rte_mcfg_mempool_read_unlock();

    return 0;
}

static int dp_vs_get_eal_mem_ring(eal_all_mem_ring_ret_t *eal_mem_rings)
{
    TAILQ_HEAD(rte_ring_list, rte_tailq_entry);
    eal_mem_ring_ret_t *ring_ret;
    const struct rte_tailq_entry *te;
    struct rte_ring_list *ring_list;
    const struct rte_ring *r = NULL;

    ring_list = RTE_TAILQ_LOOKUP("RTE_RING", rte_ring_list);

    rte_mcfg_tailq_read_lock();
    eal_mem_rings->ring_num = 0;
    TAILQ_FOREACH(te, ring_list, next) {
        r = (struct rte_ring *)te->data;
        ring_ret = &eal_mem_rings->ring_info[eal_mem_rings->ring_num];
        eal_mem_rings->ring_num++;
        memcpy(ring_ret->name, r->name, EAL_MEM_NAME_LEN);
        ring_ret->flags = r->flags;
        ring_ret->size = r->size;
        ring_ret->cons_tail = r->cons.tail;
        ring_ret->cons_head = r->cons.head;
        ring_ret->prod_tail = r->prod.tail;
        ring_ret->prod_head = r->prod.head;
        ring_ret->used = rte_ring_count(r);
        ring_ret->avail = rte_ring_free_count(r);
    }
    rte_mcfg_tailq_read_unlock();

    return 0;
}

static int dp_vs_eal_mem_get(sockoptid_t opt, const void *user, size_t len,
                void **out, size_t *outlen)
{
    eal_all_mem_seg_ret_t *all_eal_mem_seg_ret = NULL;
    eal_all_mem_zone_ret_t *all_eal_mem_zone_ret = NULL;
    eal_all_mem_pool_ret_t *all_eal_mem_pool_ret = NULL;
    eal_all_mem_ring_ret_t *all_eal_mem_ring_ret = NULL;
    int size = 0;
    int ret = EDPVS_OK;

    if (!out || !outlen)
        return EDPVS_INVAL;

    switch(opt) {
        case SOCKOPT_GET_EAL_MEM_SEG:
            size = sizeof(eal_all_mem_seg_ret_t) +
                    MAX_SEGMENT_NUM * sizeof(eal_mem_seg_ret_t);
            all_eal_mem_seg_ret = rte_zmalloc("mem_seg", size, 0);
            if (unlikely(!all_eal_mem_seg_ret)) {
                ret = EDPVS_NOMEM;
                return ret;
            }
            if (dp_vs_get_eal_mem_seg(all_eal_mem_seg_ret) < 0) {
                ret = EDPVS_DPDKAPIFAIL;
                rte_free(all_eal_mem_seg_ret);
                all_eal_mem_seg_ret = NULL;
                return ret;
            }
            *out = all_eal_mem_seg_ret;
            *outlen = sizeof(eal_all_mem_seg_ret_t) +
                    all_eal_mem_seg_ret->seg_num * sizeof(eal_mem_seg_ret_t);
            break;

        case SOCKOPT_GET_EAL_MEM_ZONE:
            size = sizeof(eal_all_mem_zone_ret_t) +
                    MAX_MEMZONE_NUM * sizeof(eal_mem_zone_ret_t);
            all_eal_mem_zone_ret = rte_zmalloc("mem_zone", size, 0);
            if (unlikely(!all_eal_mem_zone_ret)) {
                ret = EDPVS_NOMEM;
                return ret;
            }
            if (dp_vs_get_eal_mem_zone(all_eal_mem_zone_ret) < 0) {
                ret = EDPVS_DPDKAPIFAIL;
                rte_free(all_eal_mem_zone_ret);
                all_eal_mem_zone_ret = NULL;
                return ret;
            }
            *out = all_eal_mem_zone_ret;
            *outlen = sizeof(eal_all_mem_zone_ret_t) +
                    all_eal_mem_zone_ret->zone_num * sizeof(eal_mem_zone_ret_t);
            break;

        case SOCKOPT_GET_EAL_MEM_RING:
            size = sizeof(eal_all_mem_ring_ret_t) +
                    MAX_MEMZONE_NUM * sizeof(eal_mem_ring_ret_t);
            all_eal_mem_ring_ret = rte_zmalloc("mem_ring", size, 0);
            if (unlikely(!all_eal_mem_ring_ret)) {
                ret = EDPVS_NOMEM;
                return ret;
            }
            if (dp_vs_get_eal_mem_ring(all_eal_mem_ring_ret) < 0) {
                ret = EDPVS_DPDKAPIFAIL;
                rte_free(all_eal_mem_ring_ret);
                all_eal_mem_ring_ret = NULL;
                return ret;
            }
            *out = all_eal_mem_ring_ret;
            *outlen = sizeof(eal_all_mem_ring_ret_t) +
                    all_eal_mem_ring_ret->ring_num * sizeof(eal_mem_ring_ret_t);
            break;

        case SOCKOPT_GET_EAL_MEM_POOL:
            size = sizeof(eal_all_mem_pool_ret_t) +
                    MAX_MEMZONE_NUM * sizeof(eal_mem_pool_ret_t);
            all_eal_mem_pool_ret = rte_zmalloc("mem_pool", size, 0);
            if (unlikely(!all_eal_mem_pool_ret)) {
                ret = EDPVS_NOMEM;
                return ret;
            }
            if (dp_vs_get_eal_mem_pool(all_eal_mem_pool_ret) < 0) {
                ret = EDPVS_DPDKAPIFAIL;
                rte_free(all_eal_mem_pool_ret);
                all_eal_mem_pool_ret = NULL;
                return ret;
            }
            *out = all_eal_mem_pool_ret;
            *outlen = sizeof(eal_all_mem_pool_ret_t) +
                    all_eal_mem_pool_ret->mempool_num * sizeof(eal_mem_pool_ret_t);
            break;

        default:
            ret = EDPVS_INVAL;
            break;
    }

    return ret;
}

static struct dpvs_sockopts eal_mem_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_EAL_MEM_NONE,
    .set_opt_max    = SOCKOPT_SET_EAL_MEM_NONE,
    .set            = NULL,
    .get_opt_min    = SOCKOPT_GET_EAL_MEM_SEG,
    .get_opt_max    = SOCKOPT_GET_EAL_MEM_POOL,
    .get            = dp_vs_eal_mem_get,
};

int eal_mem_init(void)
{
    return sockopt_register(&eal_mem_sockopts);
}

int eal_mem_term(void)
{
    return sockopt_unregister(&eal_mem_sockopts);
}

