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
/**
 * Note: control plane only
 * based on dpvs_sockopt.
 */
#ifndef __DPVS_LADDR_CONF_H__
#define __DPVS_LADDR_CONF_H__

#include "inet.h"
#include "net/if.h"
#include "conf/match.h"
#include "conf/sockopts.h"

struct dp_vs_laddr_entry {
    int af;
    union inet_addr addr;
    uint64_t    nport_conflict;
    uint32_t    nconns;
};

typedef struct dp_vs_laddr_conf {
    /* identify service */
    int                 af_s;
    uint8_t             proto;
    union inet_addr     vaddr;
    uint16_t            vport;
    uint32_t            fwmark;

    struct dp_vs_match match;
    lcoreid_t           cid;
    lcoreid_t           index;

    /* for set */
    int                 af_l;
    union inet_addr     laddr;
    char                ifname[IFNAMSIZ];

    /* for get */
    int                 nladdrs;
    struct dp_vs_laddr_entry laddrs[0];
} dpvs_laddr_table_t;

#ifdef CONFIG_DPVS_AGENT
typedef struct dp_vs_laddr_detail {
    uint32_t af;
    uint32_t conns;
    uint64_t nport_conflict;
    union inet_addr addr;
    char ifname[IFNAMSIZ];
} dpvs_laddr_detail_t;

typedef struct dp_vs_laddr_front {
    uint32_t af;
    uint32_t port;
    uint32_t proto;
    uint32_t fwmark;
    uint32_t cid;
    uint32_t count;
    union inet_addr addr;
    struct dp_vs_match match;
    struct dp_vs_laddr_detail laddrs[0];
} dpvs_laddr_front_t;
#endif /* CONFIG_DPVS_AGENT */

#endif /* __DPVS_LADDR_CONF_H__ */
