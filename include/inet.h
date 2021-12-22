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
#ifndef __DPVS_INET_H__
#define __DPVS_INET_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "conf/common.h"
#include "conf/inet.h"

#include "dpdk.h"
#include "netif.h"

/*
 * Inet Hooks
 */
enum {
    INET_HOOK_PRE_ROUTING,
    INET_HOOK_LOCAL_IN,
    INET_HOOK_FORWARD,
    INET_HOOK_LOCAL_OUT,
    INET_HOOK_POST_ROUTING,
    INET_HOOK_NUMHOOKS,
};

struct inet_hook_state {
    unsigned int        hook;
} __rte_cache_aligned;

enum {
    INET_DROP           = 0,
    INET_ACCEPT,
    INET_STOLEN,
    INET_REPEAT,
    INET_STOP,
    INET_VERDICT_NUM,
};

typedef int (*inet_hook_fn)(void *priv, struct rte_mbuf *mbuf,
                            const struct inet_hook_state *state);

struct inet_hook_ops {
    inet_hook_fn        hook;
    unsigned int        hooknum;
    int                 af;
    void                *priv;
    int                 priority;

    struct list_head    list;
};

struct netif_port;

int INET_HOOK(int af, unsigned int hook, struct rte_mbuf *mbuf,
              struct netif_port *in, struct netif_port *out,
              int (*okfn)(struct rte_mbuf *mbuf));

int inet_init(void);
int inet_term(void);

bool inet_addr_equal(int af, const union inet_addr *a1,
                     const union inet_addr *a2);

const char *inet_proto_name(uint8_t proto);

bool inet_is_addr_any(int af, const union inet_addr *addr);

int inet_plen_to_mask(int af, uint8_t plen, union inet_addr *mask);

int inet_addr_net(int af, const union inet_addr *addr,
                  const union inet_addr *mask,
                  union inet_addr *net);

bool inet_addr_same_net(int af, uint8_t plen,
                        const union inet_addr *addr1,
                        const union inet_addr *addr2);

int inet_addr_range_dump(int af, const struct inet_addr_range *range,
                         char *buf, size_t size);

int inet_register_hooks(struct inet_hook_ops *reg, size_t n);
int inet_unregister_hooks(struct inet_hook_ops *reg, size_t n);

void inet_stats_add(struct inet_stats *stats, const struct inet_stats *diff);

#endif /* __DPVS_INET_H__ */
