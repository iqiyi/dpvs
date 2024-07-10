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
#ifndef __DPVS_NETIF_ADDR_CONF_H__
#define __DPVS_NETIF_ADDR_CONF_H__

enum {
    HW_ADDR_F_FROM_KNI   = 1,   // from linux kni device in local layer
};

struct netif_hw_addr_entry {
    char        addr[18];
    uint32_t    refcnt;
    uint16_t    flags;
    uint16_t    sync_cnt;
} __attribute__((__packed__));

struct netif_hw_addr_array {
    int     count;
    struct  netif_hw_addr_entry entries[0];
} __attribute__((__packed__));

#endif
