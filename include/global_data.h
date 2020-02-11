/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
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

#ifndef __GLOBAL_DATA_H__
#define __GLOBAL_DATA_H__

#include "conf/common.h"

typedef enum dpvs_lcore_role_type {
    LCORE_ROLE_IDLE,
    LCORE_ROLE_MASTER,
    LCORE_ROLE_FWD_WORKER,
    LCORE_ROLE_ISOLRX_WORKER,
    LCORE_ROLE_MAX
} dpvs_lcore_role_t;

extern uint64_t g_cycles_per_sec;
extern dpvs_lcore_role_t g_lcore_role[DPVS_MAX_LCORE];

/*
 *  Lcore fast search table:  g_lcore_index[index]-->cid
 *
 *  cid                 index
 *  ---------------------------
 *  master              0
 *  fwd_worker1         1
 *  fwd_worker2         2
 *  ...                 ...
 *  fwd_worker_n        n
 *  ioslrx_worker1      n+1
 *  isolrx_worker2      n+2
 *  ...                 ...
 *  isolrx_worker_m     n+m
 *
 *  anything else       -1
 * */
extern int g_lcore_index[DPVS_MAX_LCORE];

int global_data_init(void);
int global_data_term(void);

#endif
