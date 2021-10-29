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

#include <stdlib.h>
#include <string.h>
#include "conf/common.h"
#include "dpip.h"
#include "conf/eal_mem.h"
#include "sockopt.h"

static void eal_mem_help(void)
{
    fprintf(stderr,
            "Usage:\n"
            "    dpip eal-mem show [seg | ring | zone | pool] \n"
           );
}

static void list_eal_mem_seg_info(eal_all_mem_seg_ret_t *all_eal_mem_seg_ret)
{
    eal_mem_seg_ret_t *seg_ret = NULL;
    int i = 0;

    printf("%-10s %16s %16s %20s %20s %10s %10s %20s\n",
            "socket_id", "iova(Hex)", "virt_addr(Hex)", "len(KB)",
            "hugepage_size(KB)","nchannel", "nrank", "free_len(KB)");

    for (i = 0; i < all_eal_mem_seg_ret->seg_num; i++) {
        seg_ret = &all_eal_mem_seg_ret->seg_info[i];
        printf("%-10d %16lx %16lx %20lu %20lu %10u %10u %20lu\n",
                seg_ret->socket_id, seg_ret->iova, seg_ret->virt_addr,
                seg_ret->len / 1024, seg_ret->hugepage_sz / 1024,
                seg_ret->nchannel, seg_ret->nrank,
                seg_ret->free_seg_len / 1024);
    }
}

static void list_eal_mem_pool_info(eal_all_mem_pool_ret_t *all_eal_mem_pool_ret)
{
    eal_mem_pool_ret_t *mempool_ret = NULL;
    int i = 0;

    printf("%-20s %10s %10s %11s %12s %17s %10s %10s %10s\n",
            "pool_name", "flags", "elt_size", "header_size",
            "trailer_size", "private_data_size", "size", "used", "Mem(MB)");

    for (i = 0; i < all_eal_mem_pool_ret->mempool_num; i++) {
        mempool_ret = &all_eal_mem_pool_ret->mempool_info[i];
        printf("%-20s %10u %10u %11u %12u %17u %10u %10u %10llu\n",
                mempool_ret->name, mempool_ret->flags, mempool_ret->elt_size,
                mempool_ret->header_size, mempool_ret->trailer_size,
                mempool_ret->private_data_size, mempool_ret->size,
                mempool_ret->size - mempool_ret->count,
                1ULL * (mempool_ret->elt_size + mempool_ret->header_size +
                mempool_ret->trailer_size) * mempool_ret->size / 1024 / 1024);
    }
}

static void list_eal_mem_zone_info(eal_all_mem_zone_ret_t *all_eal_mem_zone_ret)
{
    eal_mem_zone_ret_t *zone_ret = NULL;
    int i = 0;

    printf("%-8s %32s %16s %16s %20s %20s %10s\n", "zone_id",
            "zone_name", "iova(Hex)", "virt_addr(Hex)", "len(KB)", "hugepage_size(KB)",
            "socket_id");

    for (i = 0; i < all_eal_mem_zone_ret->zone_num; i++) {
        zone_ret = &all_eal_mem_zone_ret->zone_info[i];
        printf("%-8d %32s %16lx %16lx %20lu %20lu %10d\n", i,
                zone_ret->name, zone_ret->iova, zone_ret->virt_addr,
                zone_ret->len / 1024, zone_ret->hugepage_sz / 1024, zone_ret->socket_id);
    }
}

static void list_eal_mem_ring_info(eal_all_mem_ring_ret_t *all_eal_mem_ring_ret)
{
    eal_mem_ring_ret_t *ring_ret = NULL;
    int i = 0;

    printf("%-20s %10s %10s %10s %10s %10s %10s %10s %10s\n",
            "ring_name", "flags", "size", "cons_tail", "cons_head",
            "prod_tail", "prod_head", "used", "avail");

    for (i = 0; i < all_eal_mem_ring_ret->ring_num; i++) {
        ring_ret = &all_eal_mem_ring_ret->ring_info[i];
        printf("%-20s %10d %10u %10u %10u %10u %10u %10u %10u\n",
                ring_ret->name, ring_ret->flags, ring_ret->size,
                ring_ret->cons_tail, ring_ret->cons_head, ring_ret->prod_tail,
                ring_ret->prod_head, ring_ret->used, ring_ret->avail);
    }
}

static int eal_mem_parse_cmd_type(struct dpip_conf *conf,
                            sockoptid_t *cmd_type)
{
    if (0 == conf->argc) {
        *cmd_type = SOCKOPT_GET_EAL_MEM_SEG;
        return 0;
    }
    else if (conf->argc > 1) {
        fprintf(stderr, "too many arguments!\n");
        eal_mem_help();
        return -1;
    }

    if (0 == strcmp(conf->argv[0], "seg")) {
        *cmd_type = SOCKOPT_GET_EAL_MEM_SEG;
    }
    else if (0 == strcmp(conf->argv[0], "zone")) {
        *cmd_type = SOCKOPT_GET_EAL_MEM_ZONE;
    }
    else if (0 == strcmp(conf->argv[0], "ring")) {
        *cmd_type = SOCKOPT_GET_EAL_MEM_RING;
    }
    else if (0 == strcmp(conf->argv[0], "pool")) {
        *cmd_type = SOCKOPT_GET_EAL_MEM_POOL;
    }
    else {
        fprintf(stderr, "eal mem parameter invalid!\n");
        eal_mem_help();
        return -1;
    }

    return 0;
}

static int eal_mem_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                       struct dpip_conf *conf)
{
    size_t size = 0;
    void *reply = NULL;
    sockoptid_t cmd_type = 0;
    int err;

    if (eal_mem_parse_cmd_type(conf, &cmd_type) != 0)
        return EDPVS_INVAL;

    err = dpvs_getsockopt(cmd_type, NULL, 0, (void **)&reply, &size);
    if (ESOCKOPT_OK != err) {
        return err;
    }

    switch (cmd_type) {
        case SOCKOPT_GET_EAL_MEM_SEG:
            list_eal_mem_seg_info((eal_all_mem_seg_ret_t *)reply);
            break;

        case SOCKOPT_GET_EAL_MEM_POOL:
            list_eal_mem_pool_info((eal_all_mem_pool_ret_t *)reply);
            break;

        case SOCKOPT_GET_EAL_MEM_ZONE:
            list_eal_mem_zone_info((eal_all_mem_zone_ret_t *)reply);
            break;

        case SOCKOPT_GET_EAL_MEM_RING:
            list_eal_mem_ring_info((eal_all_mem_ring_ret_t *)reply);
            break;
    }
    dpvs_sockopt_msg_free(reply);

    return EDPVS_OK;
}

struct dpip_obj dpip_eal_mem = {
    .name   = "eal-mem",
    .help   = eal_mem_help,
    .do_cmd = eal_mem_do_cmd,
};

static void __init eal_mem_init(void)
{
    dpip_register_obj(&dpip_eal_mem);
}

static void __exit eal_mem_exit(void)
{
    dpip_unregister_obj(&dpip_eal_mem);
}

