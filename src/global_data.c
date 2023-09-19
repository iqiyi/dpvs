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

#include <string.h>
#include <rte_cycles.h>
#include "global_data.h"

char *dpvs_pid_file;
char *dpvs_ipc_file;
char *dpvs_conf_file;

RTE_DEFINE_PER_LCORE(uint32_t, g_dpvs_poll_tick);

unsigned int g_version;
uint64_t g_cycles_per_sec;

dpvs_lcore_role_t g_lcore_role[DPVS_MAX_LCORE];
int g_lcore_index2id[DPVS_MAX_LCORE];
int g_lcore_id2index[DPVS_MAX_LCORE];

int g_lcore_num;
lcoreid_t g_master_lcore_id;
lcoreid_t g_kni_lcore_id = 0; /* By default g_kni_lcore_id is 0 and it indicates KNI core is not configured. */
uint8_t g_slave_lcore_num;
uint8_t g_isol_rx_lcore_num;
uint64_t g_slave_lcore_mask;
uint64_t g_isol_rx_lcore_mask;

int global_data_init(void)
{
    int i;

    g_cycles_per_sec = rte_get_timer_hz();
    g_lcore_num = 0;

    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        g_lcore_role[i] = LCORE_ROLE_IDLE;
        g_lcore_index2id[i] = -1;
        g_lcore_id2index[i] = -1;
    }

    return EDPVS_OK;
}

int version_parse(const char *strver)
{
    int i, j = 0;
    size_t len;
    unsigned int version = 0, mask = 0xFF;
    char *sver;

    if (strver[0] == 'v' || strver[0] == 'V') {
        sver = strdup(&strver[1]);
        len = strlen(&strver[1]);
    } else {
        sver = strdup(strver);
        len = strlen(strver);
    }

    if (unlikely(sver == NULL))
        return 0;

    for (i = 0; i < len && mask < 0xFFFFFF; i++) {
        if ('.' == sver[i] || '-' == sver[i]) {
            sver[i] = '\0';
            version = ((version << 8) | atoi(&sver[j])) & mask;
            mask |= mask << 8;
            j = i + 1;
            continue;
        }
        if (!isdigit(sver[i]))
            break;
    }
    version = ((version << 8) | atoi(&sver[j])) & mask;

    free(sver);
    return version;
}

int global_data_term(void)
{
    return EDPVS_OK;
}
