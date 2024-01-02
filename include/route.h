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
#ifndef __DPVS_ROUTE_H__
#define __DPVS_ROUTE_H__

#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>

#include "list.h"
#include "netif.h"
#include "conf/common.h"
#include "flow.h"

struct route_entry {
    uint8_t netmask;
    short metric;
    uint32_t flag;
    unsigned long mtu;
    struct list_head list;
    struct in_addr dest;
    struct in_addr gw;//0 means this a direct route
    struct in_addr src;
    struct netif_port *port;
    rte_atomic32_t refcnt;
};

struct route_entry *route4_local(uint32_t src, struct netif_port *port);

struct route_entry *route_out_local_lookup(uint32_t dest);

uint32_t route_select_addr(struct netif_port *port);

struct route_entry *route4_input(const struct rte_mbuf *mbuf,
                                const struct in_addr *daddr,
                                const struct in_addr *saddr,
                                uint8_t tos,//service type
                                const struct netif_port *port
                                );

struct route_entry *route4_output(const struct flow4 *fl4);

int route_init(void);

int route_term(void);

int route_flush(void);

static inline void route4_put(struct route_entry *route)
{
    if(route){
        if (rte_atomic32_dec_and_test(&route->refcnt)) {
            rte_free(route);
        }
    }
}

static inline void route4_get(struct route_entry *route)
{
    if(route){
        rte_atomic32_inc(&route->refcnt);
    }
}

static inline uint32_t __attribute__((pure))
        depth_to_mask(uint8_t depth)
{
    if (depth>0) {
        return (int)0x80000000 >> (depth - 1);
    }
    else
        return (int)0x0;
}

static inline bool ip_addr_netcmp(uint32_t dest, uint8_t mask,
                                  const struct route_entry *route_node)
{
    uint32_t net_mask = depth_to_mask(route_node->netmask);
    uint32_t dest_mask = depth_to_mask(mask);

    return  ((rte_be_to_cpu_32(dest) & dest_mask) == \
            (rte_be_to_cpu_32(*(uint32_t *)(&route_node->dest)) & net_mask))?1:0;
}

int route_add(struct in_addr* dest,uint8_t netmask, uint32_t flag,
              struct in_addr* gw, struct netif_port *port,
              struct in_addr* src, unsigned long mtu,short metric);

int route_del(struct in_addr* dest,uint8_t netmask, uint32_t flag,
              struct in_addr* gw, struct netif_port *port,
              struct in_addr* src, unsigned long mtu,short metric);

#endif
