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
#ifndef __DPVS_NEIGH_H__
#define __DPVS_NEIGH_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <rte_arp.h>
#include <rte_log.h>
#include <arpa/inet.h>
#include <rte_timer.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_byteorder.h>

#include "list.h"
#include "timer.h"
#include "netif.h"

int neigh_init(void);
int neigh_term(void);

#define RTE_LOGTYPE_NEIGHBOUR RTE_LOGTYPE_USER2

void neigh_keyword_value_init(void);
void install_neighbor_keywords(void);

int neigh_resolve_output(struct in_addr *nexhop, struct rte_mbuf *mbuf, struct netif_port *port);

int neigh_gratuitous_arp(struct in_addr *src, struct netif_port *port);

int neigh_resolve_input(struct rte_mbuf *mbuf, struct netif_port *port);

void neigh_process_ring(void *arg);

void neigh_confirm(struct in_addr nexthop, struct netif_port *port);

/* ethSwap(u16_t * to, u16_t * from) - Swap two 16 bit values */
static __inline__ void
uint16Swap(void *t, void *f) {
    uint16_t *d = (uint16_t *)t;
    uint16_t *s = (uint16_t *)f;
    uint16_t v;

    v = *d; *d = *s; *s = v;
}

/* ethAddrSwap( u16_t * to, u16_t * from ) - Swap two ethernet addresses */
static __inline__ void
ethAddrSwap(void *t, void *f) {
    uint16_t    *d = (uint16_t *)t;
    uint16_t    *s = (uint16_t *)f;

    uint16Swap(d++, s++);
    uint16Swap(d++, s++);
    uint16Swap(d, s); 
}

/* inetAddrSwap( void * t, void * f ) - Swap two IPv4 addresses */
static __inline__ void
inetAddrSwap(void *t, void *f) {
    uint32_t *d = (uint32_t *)t;
    uint32_t *s = (uint32_t *)f;
    uint32_t v;

    v  = *d; *d = *s; *s = v;
}

/* inetAddrCopy( void * t, void * f ) - Copy IPv4 address */
static __inline__ void
inetAddrCopy(void *t, void *f) {
    uint32_t *d = (uint32_t *)t;
    uint32_t *s = (uint32_t *)f;

    *d = *s; 
}

#endif /* __DPVS_NEIGH_H__ */
