/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2018 iQIYI (www.iqiyi.com).
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

#ifndef __DPVS_ROUTE6_CONF_H__
#define __DPVS_ROUTE6_CONF_H__

/* copied from "flow.h" */
#ifndef __DPVS_FLOW_H__
#define RTF_FORWARD     0x0400
#define RTF_LOCALIN     0x0800
#define RTF_DEFAULT     0x1000
#define RTF_KNI         0X2000
#endif

#ifndef __DPVS_ROUTE6_H__
struct rt6_prefix {
    struct in6_addr     addr;
    int                 plen;
};
#endif

enum {
    /* set */
    SOCKOPT_SET_ROUTE6_ADD_DEL  = 6300,
    SOCKOPT_SET_ROUTE6_FLUSH,

    /* get */
    SOCKOPT_GET_ROUTE6_SHOW     = 6300,
};

enum {
    RT6_OPS_GET = 1,
    RT6_OPS_ADD,
    RT6_OPS_DEL,
};

struct dp_vs_route6_conf {
    int                 af;
    int                 ops;
    struct rt6_prefix   dst;
    struct rt6_prefix   src;
    struct rt6_prefix   prefsrc;
    char                ifname[64];
    struct in6_addr     gateway;
    uint32_t            mtu;
    uint32_t            flags;
} __attribute__((__packed__));

struct dp_vs_route6_conf_array {
    int                         nroute;
    struct dp_vs_route6_conf    routes[0];
} __attribute__((__packed__));

#endif /* __DPVS_ROUTE6_CONF_H__ */
