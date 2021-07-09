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
#ifndef __DPVS_EAL_MEM_CONF__
#define __DPVS_EAL_MEM_CONF__

#include <stdio.h>
#include <string.h>

#define EAL_MEM_NAME_LEN        (32)

enum {
    /* set */
    SOCKOPT_SET_EAL_MEM_NONE = 7400,

    /* get */
    SOCKOPT_GET_EAL_MEM_SEG ,
    SOCKOPT_GET_EAL_MEM_ZONE,
    SOCKOPT_GET_EAL_MEM_RING,
    SOCKOPT_GET_EAL_MEM_POOL,
};

typedef struct eal_mem_seg_ret_s {
    uint64_t iova;
    uint64_t virt_addr;
    uint64_t len;
    uint64_t hugepage_sz;
    int socket_id;
    uint32_t nchannel;
    uint32_t nrank;
    uint64_t free_seg_len;
} eal_mem_seg_ret_t;

typedef struct eal_all_mem_seg_ret_s {
    uint32_t seg_num;
    eal_mem_seg_ret_t seg_info[0];
} eal_all_mem_seg_ret_t;

typedef struct eal_mem_zone_ret_s {
    char name[EAL_MEM_NAME_LEN];
    uint64_t iova;
    uint64_t virt_addr;
    uint64_t len;
    uint64_t hugepage_sz;
    int     socket_id;
} eal_mem_zone_ret_t;

typedef struct eal_all_mem_zone_ret_s {
    uint32_t zone_num;
    eal_mem_zone_ret_t zone_info[0];
} eal_all_mem_zone_ret_t;

typedef struct eal_mem_pool_ret_s {
    char name[EAL_MEM_NAME_LEN];
    uint32_t flags;
    uint32_t size;
    uint32_t count;
    uint32_t elt_size;
    uint32_t header_size;
    uint32_t trailer_size;
    uint32_t private_data_size;
} eal_mem_pool_ret_t;

typedef struct eal_all_mem_pool_ret_s {
    uint32_t mempool_num;
    eal_mem_pool_ret_t mempool_info[0];
} eal_all_mem_pool_ret_t;

typedef struct eal_mem_ring_ret_s {
    char name[EAL_MEM_NAME_LEN];
    int     flags;
    uint32_t size;
    uint32_t cons_tail;
    uint32_t cons_head;
    uint32_t prod_tail;
    uint32_t prod_head;
    uint32_t used;
    uint32_t avail;
} eal_mem_ring_ret_t;

typedef struct eal_all_mem_ring_ret_s {
    uint32_t ring_num;
    eal_mem_ring_ret_t ring_info[0];
} eal_all_mem_ring_ret_t;

#endif
