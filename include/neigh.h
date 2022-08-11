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
#ifndef __DPVS_NEIGH_H__
#define __DPVS_NEIGH_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

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
#include "linux_ipv6.h"

#define RTE_LOGTYPE_NEIGHBOUR RTE_LOGTYPE_USER1
#define NEIGH_TAB_BITS 8
#define NEIGH_TAB_SIZE (1 << NEIGH_TAB_BITS)
#define NEIGH_TAB_MASK (NEIGH_TAB_SIZE - 1)

struct neighbour_entry {
    int                 af;
    struct list_head    neigh_list;
    union inet_addr     ip_addr;
    struct rte_ether_addr   eth_addr;
    struct netif_port   *port;
    struct dpvs_timer   timer;
    struct list_head    queue_list;
    uint32_t            que_num;
    uint32_t            state;
    uint32_t            ts;
    uint8_t             flag;
} __rte_cache_aligned;

enum param_kind {
    NEIGH_ENTRY,
    NEIGH_PARAM
};

/*
 * no matter which kind of ip_addr, just use 32 bit to hash
 * since neighbour table is not a large table
 */
static inline unsigned int neigh_hashkey(int af,
                                         const union inet_addr *ip_addr,
                                         struct netif_port *port) {
    return rte_be_to_cpu_32(inet_addr_fold(af, ip_addr)) \
                             & NEIGH_TAB_MASK;
}

void neigh_entry_state_trans(struct neighbour_entry *neighbour, int idx);

struct neighbour_entry *neigh_lookup_entry(int af, const union inet_addr *key,
                                           const struct netif_port *port,
                                           unsigned int hashkey);

void neigh_send_mbuf_cach(struct neighbour_entry *neighbour);

int neigh_edit(struct neighbour_entry *neighbour,
               struct rte_ether_addr *eth_addr);

int neigh_init(void);

int neigh_term(void);

void neigh_keyword_value_init(void);

void install_neighbor_keywords(void);

int neigh_output(int af,
                 union  inet_addr *nexhop,
                 struct rte_mbuf *mbuf,
                 struct netif_port *port);

struct neighbour_entry *neigh_add_table(int af, const union inet_addr *ipaddr,
                                        const struct rte_ether_addr *eth_addr,
                                        struct netif_port *port,
                                        unsigned int hashkey, int flag);

int neigh_gratuitous_arp(struct in_addr *src, struct netif_port *port);

int neigh_resolve_input(struct rte_mbuf *mbuf, struct netif_port *port);

void neigh_confirm(int af, union inet_addr *nexthop, struct netif_port *port);

int neigh_sync_core(const void *param, bool add_del, enum param_kind kind);

static inline void ipv6_mac_mult(const struct in6_addr *mult_target,
                                 struct rte_ether_addr *mult_eth)
{
    uint8_t *w = (uint8_t *)mult_eth;
    w[0] = 0x33;
    w[1] = 0x33;
    rte_memcpy(&w[2], &mult_target->s6_addr32[3], 4);
}

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
