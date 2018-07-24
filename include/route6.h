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
/**
 * IPv6 route.
 */
#ifndef __DPVS_ROUTE6_H__
#define __DPVS_ROUTE6_H__
#include "flow.h"

struct rt6_prefix {
    struct in6_addr     addr;
    int                 plen;
};

struct route6 {
    struct rt6_prefix   rt6_dst;
    struct rt6_prefix   rt6_src;
    struct rt6_prefix   rt6_prefsrc;
    struct in6_addr     rt6_gateway;
    struct netif_port   *rt6_dev;
    uint32_t            rt6_mtu;
    uint32_t            rt6_flags; /* RTF_XXX */
};

struct route6 *route6_input(struct rte_mbuf *mbuf, struct flow6 *fl6);
struct route6 *route6_output(struct rte_mbuf *mbuf, struct flow6 *fl6);
int route6_put(struct route6 *rt);

int route6_init(void);
int route6_term(void);

/*test, delete me!*/
int ipv6_addr_init(void);
#endif /* __DPVS_ROUTE6_H__ */
