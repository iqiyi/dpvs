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
#ifndef __DPVS_INETADDR__
#define __DPVS_INETADDR__
/**
 * IPv4/v6 address management
 */
#include "inet.h"
#include "netif.h"
#include "timer.h"
#include "dpdk.h"
#include "list.h"


enum {
    IDEV_F_NO_IPV6  = 0x00000001,
    IDEV_F_NO_ROUTE = 0x00000002,
};

struct inet_device {
    struct netif_port   *dev;
    struct list_head    ifa_list[DPVS_MAX_LCORE];   /* inet_ifaddr list */
    struct list_head    ifm_list[DPVS_MAX_LCORE];   /* inet_ifmcaddr list*/
    uint32_t            ifa_cnt[DPVS_MAX_LCORE];
    uint32_t            ifm_cnt[DPVS_MAX_LCORE];
    rte_atomic32_t      refcnt;                     /* not used yet */
    uint32_t            flags;                      /* IDEV_F_XXX */
#define this_ifa_list   ifa_list[rte_lcore_id()]
#define this_ifm_list   ifm_list[rte_lcore_id()]
#define this_ifa_cnt    ifa_cnt[rte_lcore_id()]
#define this_ifm_cnt    ifm_cnt[rte_lcore_id()]
};

/*
 * no timer, release me by inet_ifaddr
 */
struct inet_ifmcaddr {
    struct list_head        d_list;
    struct inet_device      *idev;
    int                     af;
    union  inet_addr        addr;
    uint32_t                flags;      /* not used yet */
    uint32_t                refcnt;
};

/*
 * do not support peer address now.
 */
struct inet_ifaddr {
    struct list_head        d_list;     /* ifa_list for same inet_device */
    struct list_head        h_list;     /* global hash, key is addr */
    struct inet_device      *idev;

    int                     af;
    union inet_addr         addr;       /* primary address of iface */
    uint8_t                 plen;
    union inet_addr         mask;
    union inet_addr         bcast;

    uint8_t                 scope;
    uint32_t                flags;
    rte_atomic32_t          refcnt;
    uint32_t                valid_lft;
    uint32_t                prefered_lft;
    struct dpvs_timer       timer;
    struct timeval          tstemp;
    struct timeval          cstemp;
    /* need IPv4 ACD (RFC5227) ? */

    /* IPv6 only */
    int                     state;
    uint8_t                 dad_probes;
    struct dpvs_timer       dad_timer;

    /* per-lcore socket address pool */
    struct sa_pool          *sa_pool;
};

int inet_addr_add(int af, struct netif_port *dev,
                  const union inet_addr *addr, uint8_t plen,
                  const union inet_addr *bcast,
                  uint32_t valid_lft, uint32_t prefered_lft,
                  uint8_t scope, uint32_t flags);

int inet_addr_mod(int af, struct netif_port *dev,
                  const union inet_addr *addr, uint8_t plen,
                  const union inet_addr *bcast,
                  uint32_t valid_lft, uint32_t prefered_lft,
                  uint8_t scope);

int inet_addr_del(int af, struct netif_port *dev,
                  const union inet_addr *addr, uint8_t plen);

int inet_addr_flush(int af, struct netif_port *dev);

struct netif_port *inet_addr_get_iface(int af, union inet_addr *addr);

void inet_addr_select(int af, const struct netif_port *dev,
                      const union inet_addr *dst, int scope,
                      union inet_addr *addr);

struct inet_ifaddr *inet_addr_ifa_get(int af, const struct netif_port *dev,
                                      union inet_addr *addr);
struct inet_ifaddr *inet_addr_ifa_get_expired(int af, const struct netif_port *dev,
                                              union inet_addr *addr);
void inet_addr_ifa_put(struct inet_ifaddr *ifa);

bool inet_chk_mcast_addr(int af, struct netif_port *dev,
                        const union inet_addr *group,
                        const union inet_addr *src);

void inet_ifaddr_dad_failure(struct inet_ifaddr *ifa);

struct inet_device *dev_get_idev(const struct netif_port *dev);

void idev_put(struct inet_device *idev);

int idev_addr_init(struct inet_device *idev);


int inet_addr_init(void);
int inet_addr_term(void);

#endif /* __DPVS_INETADDR__ */
