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
 * Linux Kernel is referred.
 *
 * Lei Chen <raychen@qiyi.com>, initial, Jul 2018.
 */
#ifndef __DPVS_ROUTE6_H__
#define __DPVS_ROUTE6_H__
#include "flow.h"

/*
 * it's better to define protocol indenpendent route struct,
 * but currentlly, we use v6 route to keep more IPv4 codes
 * from being changed.
 */
struct route6 {
    struct in6_addr     rt6_dst;
    struct in6_addr     rt6_gateway;
    struct in6_addr     rt6_mask;
    uint32_t            rt6_flags; /* RTF_XXX */
    struct netif_port   *rt6_dev;
    uint32_t            rt6_mtu;
};

/* stub functions */
static inline struct route6 *route6_input(struct rte_mbuf *mbuf,
                                          struct flow6 *fl6)
{
    static struct route6 route = {
    };
    return &route;
}

static inline struct route6 *route6_output(struct rte_mbuf *mbuf,
                                           struct flow6 *fl6)
{
    static struct route6 route = {
    };
    return &route;
}

static inline int route6_put(struct route6 *rt)
{
    return 0;
}

static inline int neigh6_resolve_output(struct in6_addr *daddr,
                                        struct rte_mbuf *mbuf,
                                        struct netif_port *dev)
{
    return 0;
}

#endif /* __DPVS_ROUTE6_H__ */
