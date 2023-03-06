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
#ifndef __DPVS_ROUTE6_H__
#define __DPVS_ROUTE6_H__

#include <net/if.h>
#include "flow.h"
#include "conf/route6.h"

//#define DPVS_ROUTE6_DEBUG
#define RTE_LOGTYPE_RT6         RTE_LOGTYPE_USER1
#define RT6_METHOD_NAME_SZ      32

struct route6 {
    rt_addr_t   rt6_dst;
    rt_addr_t   rt6_src;
    rt_addr_t   rt6_prefsrc;
    struct in6_addr     rt6_gateway;
    struct netif_port   *rt6_dev;
    uint32_t            rt6_mtu;
    uint32_t            rt6_flags;  /* RTF_XXX */

    /* private members */
    uint32_t            arr_idx;    /* lpm6 array index */
    struct list_head    hnode;      /* hash list node */
    rte_atomic32_t      refcnt;
};

struct route6 *route6_input(const struct rte_mbuf *mbuf, struct flow6 *fl6);
struct route6 *route6_output(const struct rte_mbuf *mbuf, struct flow6 *fl6);
int route6_get(struct route6 *rt);
int route6_put(struct route6 *rt);

int route6_init(void);
int route6_term(void);

int route6_add(const struct in6_addr *dest, int plen, uint32_t flags,
               const struct in6_addr *gw, struct netif_port *dev,
               const struct in6_addr *src, uint32_t mtu);

int route6_del(const struct in6_addr *dest, int plen, uint32_t flags,
               const struct in6_addr *gw, struct netif_port *dev,
               const struct in6_addr *src, uint32_t mtu);

/* for route6_xxx.c only */
void route6_free(struct route6*);

static inline int dump_rt6_prefix(const rt_addr_t *rt6_p, char *buf, int len)
{
    size_t rlen;

    if (!inet_ntop(AF_INET6, &rt6_p->addr, buf, len))
        return 0;

    rlen = strlen(buf);
    rlen += snprintf(buf+rlen, len-rlen, "/%d", rt6_p->plen);

    return rlen;
}

struct route6_method {
    char name[RT6_METHOD_NAME_SZ];
    struct list_head lnode;
    int (*rt6_setup_lcore)(void *);
    int (*rt6_destroy_lcore)(void *);
    uint32_t (*rt6_count)(void);
    int (*rt6_add_lcore)(const struct dp_vs_route6_conf *);
    int (*rt6_del_lcore)(const struct dp_vs_route6_conf *);
    struct route6* (*rt6_get)(const struct dp_vs_route6_conf *);
    struct route6* (*rt6_input)(const struct rte_mbuf *, struct flow6 *);
    struct route6* (*rt6_output)(const struct rte_mbuf *, struct flow6 *);
    struct dp_vs_route6_conf_array* (*rt6_dump)(
            const struct dp_vs_route6_conf *rt6_cfg,
            size_t *nbytes);
};

int route6_method_register(struct route6_method *rt6_mtd);
int route6_method_unregister(struct route6_method *rt6_mtd);

static inline void rt6_fill_with_cfg(struct route6 *rt6,
        const struct dp_vs_route6_conf *cf)
{
    memset(rt6, 0, sizeof(struct route6));

    rt6->rt6_dst = cf->dst;
    rt6->rt6_src = cf->src;
    rt6->rt6_prefsrc = cf->prefsrc;
    rt6->rt6_dev = netif_port_get_by_name(cf->ifname);
    rt6->rt6_gateway = cf->gateway;
    rt6->rt6_flags = cf->flags;
    rt6->rt6_mtu = cf->mtu;
    if (!cf->mtu && rt6->rt6_dev)
        rt6->rt6_mtu = rt6->rt6_dev->mtu;
}

static inline void rt6_fill_cfg(struct dp_vs_route6_conf *cf,
        const struct route6 *rt6)
{
    memset(cf, 0, sizeof(struct dp_vs_route6_conf));

    cf->dst = rt6->rt6_dst;
    cf->src = rt6->rt6_src;
    cf->prefsrc = rt6->rt6_prefsrc;

    strncpy(cf->ifname, rt6->rt6_dev->name, sizeof(cf->ifname));
    cf->gateway = rt6->rt6_gateway;
    cf->mtu = rt6->rt6_mtu;
    cf->flags = rt6->rt6_flags;
}

void install_route6_keywords(void);
void route6_keyword_value_init(void);

#endif /* __DPVS_ROUTE6_H__ */
