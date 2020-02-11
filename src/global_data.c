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

#include <rte_cycles.h>
#include "global_data.h"
#include "conf/common.h"

uint64_t g_cycles_per_sec;
dpvs_lcore_role_t g_lcore_role[DPVS_MAX_LCORE];
int g_lcore_index[DPVS_MAX_LCORE];

int global_data_init(void)
{
    int i;

    g_cycles_per_sec = rte_get_timer_hz();

    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        g_lcore_role[i] = LCORE_ROLE_IDLE;
        g_lcore_index[i] = -1;
    }

    return EDPVS_OK;
}

int global_data_term(void)
{
    return EDPVS_OK;
}
