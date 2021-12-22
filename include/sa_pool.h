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
/*
 * socket address (or local <ip, port> pair) pool.
 *
 * for multi-core app, the traffic comes back of local initiated
 * connection need reach original CPU core. there are several
 * ways to achieve the goal. one is to calc RSS the same way of
 * NIC to select the correct CPU for connect.
 *
 * the way we use is based on DPDK Generic Flow(rte_flow), allocate
 * local source (e.g., <ip, port>) for each CPU core in advance.
 * and redirect the back traffic to that CPU by rte_flow. it does not
 * need two many flow rules, the number of rules can be equal to
 * the number of CPU core.
 *
 * LVS use laddr and try <laddr,lport> to see if is used when
 * allocation. if the pair occupied it continue to use next port
 * and trails for thounds of times unitl given up. it causes CPU
 * wasting and the resource (lport) is not fully used. So we use
 * a pool to save pre-allocated resource, fetch the pair from pool
 * when needed, release it after used. no trial needed, it's
 * efficient and all resource available can be used.
 *
 * Lei Chen <raychen@qiyi.com>, June 2017, initial.
 */
#ifndef __DPVS_SA_POOL__
#define __DPVS_SA_POOL__

#include "netif_flow.h"

#define MAX_PORT            65536
#define MAX_SA_FLOW         4

struct sa_pool_stats {
    uint32_t used_cnt;
    uint32_t free_cnt;
    uint32_t miss_cnt;
};

/**
 * if really need to to save memory, we can;
 * 1. use hlist_head
 * 2. use uint8_t flag
 * 3. remove sa_entry.addr, and get IP from sa_pool->ifa
 * 4. to __packed__ sa_entry.
 * 5. create sa_entry_pool only if pool_hash hit.
 *    since when dest (like RS) num may small.
 */

/* socket address (sa) is <ip, port> pair. */
struct sa_entry {
    struct list_head        list;       /* node of sa_pool. */
    uint32_t                flags;      /* SA_F_XXX */
    union inet_addr         addr;
    __be16                  port;
};

struct sa_entry_pool {
    struct sa_entry         *sa_entries;
    struct list_head        used_enties;
    struct list_head        free_enties;
    /* another way is use total_used/free_cnt in sa_pool,
     * so that we need not travels the hash to get stats.
     * we use cnt here, since we may need per-pool stats. */
    uint16_t                used_cnt;
    uint16_t                free_cnt;
    uint32_t                miss_cnt;
    uint16_t                shift;
};

/* no lock needed because inet_ifaddr.sa_pool
 * is per-lcore. */
struct sa_pool {
    struct inet_ifaddr          *ifa;       /* back-pointer */

    uint16_t                    low;        /* min port */
    uint16_t                    high;       /* max port */
    rte_atomic32_t              refcnt;

    /* hashed pools by dest's <ip/port>. if no dest provided,
     * just use first pool. it's not need create/destroy pool
     * for each dest, that'll be too complicated. */
    struct sa_entry_pool        *pool_hash;
    uint8_t                     pool_hash_sz;
    uint32_t                    flags;      /* SA_POOL_F_XXX */

    int                         flow_num;
    struct netif_flow_handler   flows[MAX_SA_FLOW];
};

int sa_pool_init(void);
int sa_pool_term(void);

int sa_pool_create(struct inet_ifaddr *ifa, uint16_t low, uint16_t high);
int sa_pool_destroy(struct inet_ifaddr *ifa);

/**
 * @dev and @daddr is optional,
 * note: if @daddr is used, it must be the same for sa_fetch and sa_release.
 */
int sa_fetch(int af, struct netif_port *dev,
             const struct sockaddr_storage *daddr,
             struct sockaddr_storage *saddr);

int sa_release(const struct netif_port *dev,
               const struct sockaddr_storage *daddr,
               const struct sockaddr_storage *saddr);

int get_sa_pool_stats(const struct inet_ifaddr *ifa,
                       struct sa_pool_stats *stats);

/* config file */
void install_sa_pool_keywords(void);

static inline void hold_ifa_sa_pool(struct inet_ifaddr *ifa)
{
    rte_atomic32_inc(&ifa->sa_pool->refcnt);
}

#endif /* __DPVS_SA_POOL__ */
