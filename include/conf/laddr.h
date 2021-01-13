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
#include "conf/sockopts.h"

struct dp_vs_laddr_entry {
    int af;
    union inet_addr addr;
    uint64_t    nport_conflict;
    uint32_t    nconns;
};

struct dp_vs_laddr_conf {
    /* identify service */
    int                 af_s;
    uint8_t             proto;
    union inet_addr     vaddr;
    uint16_t            vport;
    uint32_t            fwmark;
    char                srange[256];
    char                drange[256];
    char                iifname[IFNAMSIZ];
    char                oifname[IFNAMSIZ];
    lcoreid_t           cid;

    /* for set */
    int                 af_l;
    union inet_addr     laddr;
    char                ifname[IFNAMSIZ];

    /* for get */
    int                 nladdrs;
    struct dp_vs_laddr_entry laddrs[0];
};

#endif /* __DPVS_LADDR_CONF_H__ */
