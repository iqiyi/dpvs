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
#ifndef __DPVS_ROUTE_H__
#define __DPVS_ROUTE_H__

#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>

#include "list.h"
#include "netif.h"
#include "common.h"

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

struct flow4 {
    struct in_addr saddr;
    struct in_addr daddr;
    uint16_t sport;
    uint16_t dport;
    struct netif_port *oif;
    struct netif_port *iif;
    uint8_t tos;
    uint8_t proto;
    uint8_t scope;
    uint8_t ttl;
    uint32_t mark;
    uint32_t flags;
};

#define RTF_UP      0x0001      /* route usable         */
#define RTF_GATEWAY 0x0002      /* destination is a gateway */
#define RTF_HOST    0x0004      /* host entry (net otherwise)   */
#define RTF_REINSTATE   0x0008      /* reinstate route after tmout  */
#define RTF_DYNAMIC 0x0010      /* created dyn. (by redirect)   */
#define RTF_MODIFIED    0x0020      /* modified dyn. (by redirect)  */
#define RTF_MTU     0x0040      /* specific MTU for this route  */
#define RTF_MSS     RTF_MTU     /* Compatibility :-(        */
#define RTF_WINDOW  0x0080      /* per route window clamping    */
#define RTF_IRTT    0x0100      /* Initial round trip time  */
#define RTF_REJECT  0x0200      /* Reject route         */

#define RTF_FORWARD 0x0400
#define RTF_LOCALIN 0x0800
#define RTF_DEFAULT 0x1000
#define RTF_KNI     0X2000

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
        rte_atomic32_dec(&route->refcnt);
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
