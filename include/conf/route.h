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
#ifndef __DPVS_ROUTE_CONF_H__
#define __DPVS_ROUTE_CONF_H__

#include "flow.h"
#include "inet.h"
#include "net/if.h"
#include "conf/sockopts.h"

enum {
    ROUTE_CF_SCOPE_NONE     = 0,
    ROUTE_CF_SCOPE_HOST,
    ROUTE_CF_SCOPE_KNI,
    ROUTE_CF_SCOPE_LINK,
    ROUTE_CF_SCOPE_GLOBAL,
};

enum {
    ROUTE_CF_PROTO_AUTO     = 0,
    ROUTE_CF_PROTO_BOOT,
    ROUTE_CF_PROTO_STATIC,
    ROUTE_CF_PROTO_RA,
    ROUTE_CF_PROTO_REDIRECT,
};

enum {
    ROUTE_CF_FLAG_ONLINK,
};

struct dp_vs_route_conf {
    int             af;
    union inet_addr dst;    /* all-zero for default */
    uint8_t         plen;   /* prefix length */
    union inet_addr via;
    union inet_addr src;
    char            ifname[IFNAMSIZ];
    uint32_t        mtu;
    uint8_t         tos;
    uint8_t         scope;
    uint8_t         metric;
    uint8_t         proto;  /* routing protocol */
    uint32_t        flags;
} __attribute__((__packed__));

typedef struct dp_vs_route_detail {
    uint32_t    af;
    uint32_t    mtu;
    uint32_t    flags;
    uint32_t    metric;
    rt_addr_t   dst;
    rt_addr_t   src;
    rt_addr_t   gateway;
    rt_addr_t   prefsrc;
    char        ifname[IFNAMSIZ];
} dpvs_route_detail_t;

struct dp_vs_route_conf_array {
    int                 nroute;
    struct dp_vs_route_detail   routes[0];
} __attribute__((__packed__));

#endif /* __DPVS_ROUTE_CONF_H__ */
