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
/**
 * Note: control plane only
 * based on dpvs_sockopt.
 */
#ifndef __DPVS_WHTLST_CONF_H__
#define __DPVS_WHTLST_CONF_H__
#include "inet.h"
#include "conf/sockopts.h"
struct dp_vs_whtlst_entry {
    union inet_addr addr;
};

struct dp_vs_whtlst_conf {
    /* identify service */
    int                 af;
    uint8_t             proto;
    union inet_addr     vaddr;
    uint16_t            vport;
    uint32_t            fwmark;

    /* for set */
    union inet_addr     whtlst;
};

struct dp_vs_whtlst_conf_array {
    int                 naddr;
    struct dp_vs_whtlst_conf   whtlsts[0];
} __attribute__((__packed__));

#endif /* __DPVS_WHTLST_CONF_H__ */
