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
 * NIC to select the currect CPU for connect.
 *
 * the way we use is based on DPDK Generic Flow(rte_flow), allocate
 * local source (e.g., <ip, port>) for each CPU core in advance.
 * and redirect the back traffic to that CPU by rte_flow. it does not
 * need too many flow rules, the number of rules can be equal to
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
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include "list.h"
#include "dpdk.h"
#include "inet.h"
#include "netif.h"
#include "route.h"
#include "route6.h"
#include "ctrl.h"
#include "sa_pool.h"
#include "linux_ipv6.h"
#include "parser/parser.h"
#include "parser/vector.h"

#define DEF_MIN_PORT        1025
#define DEF_MAX_PORT        65535

#define SAPOOL
#define RTE_LOGTYPE_SAPOOL  RTE_LOGTYPE_USER1

#define SAPOOL_DEF_HASH_SZ  16
#define SAPOOL_MIN_HASH_SZ  1
#define SAPOOL_MAX_HASH_SZ  128

enum {
    SA_F_USED               = 0x01,
};

struct sa_flow {
    /* the ports one lcore can use means
     * "(sa_flow.mask & port) == port_base" */
    uint16_t                mask;       /* filter's port mask */
    lcoreid_t               lcore;
    __be16                  port_base;
    uint16_t                shift;
};

static struct sa_flow       sa_flows[DPVS_MAX_LCORE];

static uint8_t              sa_nlcore;
static uint64_t             sa_lcore_mask;

static uint8_t              sa_pool_hash_size  = SAPOOL_DEF_HASH_SZ;
static bool                 sapool_flow_enable = true;

static int sa_pool_alloc_hash(struct sa_pool *ap, uint8_t hash_sz,
                               const struct sa_flow *flow)
{
    int hash;
    struct sa_entry_pool *pool;
    struct sa_entry * sep;
    uint32_t port; /* should be u32 or 65535==0 */
    uint32_t sa_entry_pool_size;
    uint32_t sa_entry_size;
    uint32_t sa_entry_num;

    sa_entry_num = MAX_PORT >> flow->shift;
    sa_entry_pool_size = sizeof(struct sa_entry_pool) * hash_sz;
    sa_entry_size = sizeof(struct sa_entry) * sa_entry_num * hash_sz;

    ap->pool_hash = rte_malloc(NULL, sa_entry_pool_size + sa_entry_size,
                               RTE_CACHE_LINE_SIZE);
    if (!ap->pool_hash)
        return EDPVS_NOMEM;

    ap->pool_hash_sz = hash_sz;
    sep = (struct sa_entry *)&ap->pool_hash[hash_sz];

    /* the big loop may take tens of milliseconds */
    for (hash = 0; hash < hash_sz; hash++) {
        pool = &ap->pool_hash[hash];

        INIT_LIST_HEAD(&pool->used_enties);
        INIT_LIST_HEAD(&pool->free_enties);

        pool->used_cnt = 0;
        pool->free_cnt = 0;
        pool->shift = flow->shift;
        pool->sa_entries = &sep[sa_entry_num * hash];

        for (port = ap->low; port <= ap->high; port++) {
            struct sa_entry *sa;

            if (flow->mask &&
                ((uint16_t)port & flow->mask) != ntohs(flow->port_base))
                continue;

            sa = &pool->sa_entries[(uint16_t)(port >> pool->shift)];
            sa->addr = ap->ifa->addr;
            sa->port = htons((uint16_t)port);
            list_add_tail(&sa->list, &pool->free_enties);
            pool->free_cnt++;
        }
    }

    return EDPVS_OK;
}

static int sa_pool_free_hash(struct sa_pool *ap)
{
    /* FIXME: it may take about 3ms to free the huge `sa->pool_hash`, and
     * @rte_free uses a spinlock to protect its heap. If multiple workers
     * free their sapools simultaneously, a worker may be stuck up to 3*N ms,
     * where `N` is the dpvs worker number.
     *
     * use mempool for sapool could solve the problem. we still use @rte_free
     * here considering sapool is not frequently changed.
     */
    rte_free(ap->pool_hash);    /* it may take up to 3ms */
    ap->pool_hash_sz = 0;
    return EDPVS_OK;
}

static int sa_pool_add_filter(struct inet_ifaddr *ifa, struct sa_pool *ap,
                             lcoreid_t cid)
{
    int err;
    struct sa_flow *flow = &sa_flows[cid];

    netif_flow_handler_param_t flow_handlers = {
            .size     = MAX_SA_FLOW,
            .flow_num = 0,
            .handlers = ap->flows,
    };

    if (!sapool_flow_enable)
        return EDPVS_OK;

    err = netif_sapool_flow_add(ifa->idev->dev, cid, ifa->af, &ifa->addr,
            flow->port_base, htons(flow->mask), &flow_handlers);
    ap->flow_num = flow_handlers.flow_num;

    return err;
}

static int sa_pool_del_filter(struct inet_ifaddr *ifa, struct sa_pool *ap,
                               lcoreid_t cid)
{
    struct sa_flow *flow = &sa_flows[cid];

    netif_flow_handler_param_t flow_handlers = {
            .size     = MAX_SA_FLOW,
            .flow_num = ap->flow_num,
            .handlers = ap->flows,
    };

    if (!sapool_flow_enable)
        return EDPVS_OK;

    return netif_sapool_flow_del(ifa->idev->dev, cid, ifa->af, &ifa->addr,
            flow->port_base, htons(flow->mask), &flow_handlers);
}

int sa_pool_create(struct inet_ifaddr *ifa, uint16_t low, uint16_t high)
{
    int err;
    struct sa_pool *ap;
    lcoreid_t cid = rte_lcore_id();

    if (cid > 64 || !((sa_lcore_mask & (1UL << cid)))) {
        if (cid == rte_get_main_lcore())
            return EDPVS_OK; /* no sapool on master */
        return EDPVS_INVAL;
    }

    low = low ? : DEF_MIN_PORT;
    high = high ? : DEF_MAX_PORT;

    if (!ifa || low > high || low == 0 || high >= MAX_PORT) {
        RTE_LOG(ERR, SAPOOL, "%s: bad arguments\n", __func__);
        return EDPVS_INVAL;
    }

    ap = rte_zmalloc(NULL, sizeof(struct sa_pool), 0);
    if (unlikely(!ap))
        return EDPVS_NOMEM;

    ap->ifa = ifa;
    ap->low = low;
    ap->high = high;
    ap->flags = 0;
    rte_atomic32_set(&ap->refcnt, 1);

    err = sa_pool_alloc_hash(ap, sa_pool_hash_size, &sa_flows[cid]);
    if (err != EDPVS_OK) {
        goto free_ap;
    }

    err = sa_pool_add_filter(ifa, ap, cid);
    if (err != EDPVS_OK) {
        goto free_hash;
    }

    ifa->sa_pool = ap;

    /* inc ifa->refcnt to hold it */
    rte_atomic32_inc(&ifa->refcnt);

#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    {
        char addr[64];
        RTE_LOG(INFO, SAPOOL, "[%02d] %s: sa pool created -- %s\n", rte_lcore_id(),
                __func__, inet_ntop(ifa->af, &ifa->addr, addr, sizeof(addr)) ? : NULL);
    }
#endif

    return EDPVS_OK;

free_hash:
    sa_pool_free_hash(ap);
free_ap:
    rte_free(ap);
    return err;
}

/*
 * the func name @sa_pool_destroy is a litle confusing, its more reasonable
 * name may be something like `sa_pool_put`. we keep the name to correspond
 * with @sa_pool_create.
 * */
int sa_pool_destroy(struct inet_ifaddr *ifa)
{
    int err;
    struct sa_pool *ap;
    lcoreid_t cid = rte_lcore_id();

    if (cid > 64 || !((sa_lcore_mask & (1UL << cid)))) {
        if (cid == rte_get_main_lcore())
            return EDPVS_OK;
        return EDPVS_INVAL;
    }

    if (!ifa || !ifa->sa_pool)
        return EDPVS_INVAL;
    ap = ifa->sa_pool;

    if (!rte_atomic32_dec_and_test(&ap->refcnt))
        return EDPVS_OK;

    err = sa_pool_del_filter(ifa, ap, cid);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SAPOOL, "[%02d] %s: sa_del_filter failed -- %s\n",
                cid, __func__, dpvs_strerror(err));
        return err;
    }

    sa_pool_free_hash(ap);
    rte_free(ap);

    ifa->sa_pool = NULL;

#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    {
        char addr[64];
        RTE_LOG(INFO, SAPOOL, "[%02d] %s: sa pool destroyed -- %s\n", rte_lcore_id(),
                __func__, inet_ntop(ifa->af, &ifa->addr, addr, sizeof(addr)) ? : NULL);
    }
#endif

    /* release ifa held by @sa_pool_create */
    inet_addr_ifa_put(ifa);

    return EDPVS_OK;
}

/* hash dest's <ip/port>. if no dest provided, just use first pool. */
static inline struct sa_entry_pool *
sa_pool_hash(const struct sa_pool *ap, const struct sockaddr_storage *ss)
{
    uint32_t hashkey;
    assert(ap && ap->pool_hash && ap->pool_hash_sz >= 1);
    if (!ss)
        return &ap->pool_hash[0];

    if (ss->ss_family == AF_INET) {
        uint16_t vect[2];
        const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;

        vect[0] = ntohl(sin->sin_addr.s_addr) & 0xffff;
        vect[1] = ntohs(sin->sin_port);
        hashkey = (vect[0] + vect[1]) % ap->pool_hash_sz;

        return &ap->pool_hash[hashkey];
    } else if (ss->ss_family == AF_INET6) {
        uint32_t vect[5] = { 0 };
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;

        vect[0] = sin6->sin6_port;
        memcpy(&vect[1], &sin6->sin6_addr, 16);
        hashkey = rte_jhash_32b(vect, 5, sin6->sin6_family) % ap->pool_hash_sz;

        return &ap->pool_hash[hashkey];
    } else {
        return NULL;
    }
}

static inline int sa_pool_fetch(struct sa_entry_pool *pool,
                                struct sockaddr_storage *ss)
{
    assert(pool && ss);

    struct sa_entry *ent;
    struct sockaddr_in *sin = (struct sockaddr_in *)ss;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

    ent = list_first_entry_or_null(&pool->free_enties, struct sa_entry, list);
    if (!ent) {
#ifdef CONFIG_DPVS_SAPOOL_DEBUG
        RTE_LOG(DEBUG, SAPOOL, "%s: no entry (used/free %d/%d)\n", __func__,
                pool->used_cnt, pool->free_cnt);
#endif
        pool->miss_cnt++;
        return EDPVS_RESOURCE;
    }

    if (ss->ss_family == AF_INET) {
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = ent->addr.in.s_addr;
        sin->sin_port = ent->port;
    } else if (ss->ss_family == AF_INET6) {
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = ent->addr.in6;
        sin6->sin6_port = ent->port;
    } else {
        return EDPVS_NOTSUPP;
    }

    ent->flags |= SA_F_USED;
    list_move_tail(&ent->list, &pool->used_enties);
    pool->used_cnt++;
    pool->free_cnt--;

#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    {
        char addr[64];
        RTE_LOG(DEBUG, SAPOOL, "%s: %s:%d fetched!\n", __func__,
                inet_ntop(ss->ss_family, &ent->addr, addr, sizeof(addr)) ? : NULL,
                ntohs(ent->port));
    }
#endif

    return EDPVS_OK;
}

static inline int sa_pool_release(struct sa_entry_pool *pool,
                                  const struct sockaddr_storage *ss)
{
    assert(pool && ss);

    struct sa_entry *ent;
    const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;
    __be16 port;

    if (ss->ss_family == AF_INET)
        port = ntohs(sin->sin_port);
    else if (ss->ss_family == AF_INET6)
        port = ntohs(sin6->sin6_port);
    else
        return EDPVS_NOTSUPP;
    assert(port > 0 && port < MAX_PORT);

    /* it's too slow to traverse the used_enties list
     * (by list_for_each_entry_safe) to find the @entry
     * matchs @sin. */
    ent = &pool->sa_entries[port >> pool->shift];
    if (!(ent->flags & SA_F_USED)) {
        RTE_LOG(WARNING, SAPOOL, "%s: port %d not in use !\n", __func__, port);
        return EDPVS_INVAL;
    }

    if (ss->ss_family == AF_INET)
        assert(ent->addr.in.s_addr == sin->sin_addr.s_addr &&
                ent->port == sin->sin_port);
    else
        assert(ipv6_addr_equal(&ent->addr.in6, &sin6->sin6_addr) &&
                ent->port == sin6->sin6_port);

    ent->flags &= (~SA_F_USED);
    list_move_tail(&ent->list, &pool->free_enties);
    pool->used_cnt--;
    pool->free_cnt++;

#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    {
        char addr[64];
        RTE_LOG(DEBUG, SAPOOL, "%s: %s:%d released!\n", __func__,
                inet_ntop(ss->ss_family, &ent->addr, addr, sizeof(addr)) ? : NULL,
                ntohs(ent->port));
    }
#endif

    return EDPVS_OK;
}

/*
 * fetch unused <saddr, sport> pair by given hint.
 * given @ap equivalent to @dev+@saddr, and dport is useless.
 * with routing's help, the mapping looks like,
 *
 * +------+------------+-------+-------------------
 * |      |     ap     |       | Is possible to
 * |daddr | dev & saddr| sport | fetch addr pair?
 * +------+------------+-------+-------------------
 *    Y      Y     ?       Y       Possible
 *    Y      Y     Y       ?       Possible
 *    Y      Y     ?       ?       Possible
 *    Y      N     ?       Y       Possible
 *    Y      N     Y       ?       Possible
 *    Y      N     ?       ?       Possible
 *    N      Y     ?       Y       Possible
 *    N      Y     Y       ?       Possible
 *    N      Y     ?       ?       Possible
 *    N      N     ?       Y       Not Possible
 *    N      N     Y       ?       Possible
 *    N      N     ?       ?       Not Possible
 *
 * daddr is a hint to found dev/saddr (by route/netif module).
 * dev is also a hint, the saddr(ifa) is the key.
 * af is needed when both saddr and daddr are NULL.
 */
static int sa4_fetch(struct netif_port *dev,
                     const struct sockaddr_in *daddr,
                     struct sockaddr_in *saddr)
{
    struct inet_ifaddr *ifa;
    struct flow4 fl;
    struct route_entry *rt;
    int err;
    assert(saddr);

    if (saddr && saddr->sin_addr.s_addr != INADDR_ANY && saddr->sin_port != 0)
        return EDPVS_OK; /* everything is known, why call this function ? */

    /* if source IP is assiged, we can find ifa->sa_pool
     * without @daddr and @dev. */
    if (saddr->sin_addr.s_addr) {
        ifa = inet_addr_ifa_get(AF_INET, dev, (union inet_addr*)&saddr->sin_addr);
        if (!ifa)
            return EDPVS_NOTEXIST;

        if (!ifa->sa_pool) {
            RTE_LOG(WARNING, SAPOOL, "%s: fetch addr on IP without sapool.", __func__);
            inet_addr_ifa_put(ifa);
            return EDPVS_INVAL;
        }

        err = sa_pool_fetch(sa_pool_hash(ifa->sa_pool,
                            (struct sockaddr_storage *)daddr),
                            (struct sockaddr_storage *)saddr);
        if (err == EDPVS_OK)
            rte_atomic32_inc(&ifa->sa_pool->refcnt);
        inet_addr_ifa_put(ifa);
        return err;
    }

    /* try to find source ifa by @dev and @daddr */
    memset(&fl, 0, sizeof(struct flow4));
    fl.fl4_oif = dev;
    fl.fl4_daddr.s_addr = daddr ? daddr->sin_addr.s_addr : htonl(INADDR_ANY);
    fl.fl4_saddr.s_addr = saddr ? saddr->sin_addr.s_addr : htonl(INADDR_ANY);
    rt = route4_output(&fl);
    if (!rt)
        return EDPVS_NOROUTE;

    /* select source address. */
    if (!rt->src.s_addr) {
        inet_addr_select(AF_INET, rt->port, (union inet_addr *)&rt->dest,
                         RT_SCOPE_UNIVERSE, (union inet_addr *)&rt->src);
    }
    ifa = inet_addr_ifa_get(AF_INET, rt->port, (union inet_addr *)&rt->src);
    if (!ifa) {
        route4_put(rt);
        return EDPVS_NOTEXIST;
    }
    route4_put(rt);

    if (!ifa->sa_pool) {
        RTE_LOG(WARNING, SAPOOL, "%s: fetch addr on IP without pool.",
                __func__);
        inet_addr_ifa_put(ifa);
        return EDPVS_INVAL;
    }

    /* do fetch socket address */
    err = sa_pool_fetch(sa_pool_hash(ifa->sa_pool,
                        (struct sockaddr_storage *)daddr),
                        (struct sockaddr_storage *)saddr);
    if (err == EDPVS_OK)
        rte_atomic32_inc(&ifa->sa_pool->refcnt);

    inet_addr_ifa_put(ifa);
    return err;
}

static int sa6_fetch(struct netif_port *dev,
                     const struct sockaddr_in6 *daddr,
                     struct sockaddr_in6 *saddr)
{
    struct inet_ifaddr *ifa;
    struct flow6 fl6;
    struct route6 *rt6;
    int err;
    assert(saddr);

    if (saddr && !ipv6_addr_any(&saddr->sin6_addr) && saddr->sin6_port != 0)
        return EDPVS_OK; /* everything is known, why call this function ? */

    /* if source IP is assiged, we can find ifa->sa_pool
     * without @daddr and @dev. */
    if (!ipv6_addr_any(&saddr->sin6_addr)) {
        ifa = inet_addr_ifa_get(AF_INET6, dev, (union inet_addr*)&saddr->sin6_addr);
        if (!ifa)
            return EDPVS_NOTEXIST;

        if (!ifa->sa_pool) {
            RTE_LOG(WARNING, SAPOOL, "%s: fetch addr on IP without pool.", __func__);
            inet_addr_ifa_put(ifa);
            return EDPVS_INVAL;
        }

        err = sa_pool_fetch(sa_pool_hash(ifa->sa_pool,
                            (struct sockaddr_storage *)daddr),
                            (struct sockaddr_storage *)saddr);
        if (err == EDPVS_OK)
            rte_atomic32_inc(&ifa->sa_pool->refcnt);
        inet_addr_ifa_put(ifa);
        return err;
    }

    /* try to find source ifa by @dev and @daddr */
    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_oif = dev;
    if (daddr)
        fl6.fl6_daddr= daddr->sin6_addr;
    if (saddr)
        fl6.fl6_saddr= saddr->sin6_addr;
    rt6 = route6_output(NULL, &fl6);
    if (!rt6)
        return EDPVS_NOROUTE;

    /* select source address. */
    if (ipv6_addr_any(&rt6->rt6_src.addr.in6)) {
        inet_addr_select(AF_INET6, rt6->rt6_dev,
                         (union inet_addr *)&rt6->rt6_dst.addr,
                         RT_SCOPE_UNIVERSE,
                         (union inet_addr *)&rt6->rt6_src.addr);
    }
    ifa = inet_addr_ifa_get(AF_INET6, rt6->rt6_dev,
                    (union inet_addr *)&rt6->rt6_src.addr);
    if (!ifa) {
        route6_put(rt6);
        return EDPVS_NOTEXIST;
    }
    route6_put(rt6);

    if (!ifa->sa_pool) {
        RTE_LOG(WARNING, SAPOOL, "%s: fetch addr on IP without pool.",
                __func__);
        inet_addr_ifa_put(ifa);
        return EDPVS_INVAL;
    }

    /* do fetch socket address */
    err = sa_pool_fetch(sa_pool_hash(ifa->sa_pool,
                        (struct sockaddr_storage *)daddr),
                        (struct sockaddr_storage *)saddr);
    if (err == EDPVS_OK)
        rte_atomic32_inc(&ifa->sa_pool->refcnt);

    inet_addr_ifa_put(ifa);
    return err;
}

int sa_fetch(int af, struct netif_port *dev,
             const struct sockaddr_storage *daddr,
             struct sockaddr_storage *saddr)
{
    if (unlikely(daddr && daddr->ss_family != af))
        return EDPVS_INVAL;
    if (unlikely(saddr && saddr->ss_family != af))
        return EDPVS_INVAL;
    if (AF_INET == af)
        return sa4_fetch(dev, (const struct sockaddr_in *)daddr,
                (struct sockaddr_in *)saddr);
    else if (AF_INET6 == af)
        return sa6_fetch(dev, (const struct sockaddr_in6 *)daddr,
                (struct sockaddr_in6 *)saddr);
    else
        return EDPVS_NOTSUPP;
}

/* call me with @saddr must not NULL */
int sa_release(const struct netif_port *dev,
               const struct sockaddr_storage *daddr,
               const struct sockaddr_storage *saddr)
{
    struct inet_ifaddr *ifa;
    int err;

    if (!saddr)
        return EDPVS_INVAL;

    if (daddr && saddr->ss_family != daddr->ss_family)
        return EDPVS_INVAL;

    if (AF_INET == saddr->ss_family) {
        const struct sockaddr_in *saddr4 = (const struct sockaddr_in *)saddr;
        ifa = inet_addr_ifa_get(AF_INET, dev,
                (union inet_addr*)&saddr4->sin_addr);
        if (unlikely(!ifa))
            ifa = inet_addr_ifa_get_expired(AF_INET, dev,
                    (union inet_addr*)&saddr4->sin_addr);
    } else if (AF_INET6 == saddr->ss_family) {
        const struct sockaddr_in6 *saddr6 = (const struct sockaddr_in6 *)saddr;
        ifa = inet_addr_ifa_get(AF_INET6, dev,
                (union inet_addr*)&saddr6->sin6_addr);
        if (unlikely(!ifa))
            ifa = inet_addr_ifa_get_expired(AF_INET6, dev,
                    (union inet_addr*)&saddr6->sin6_addr);
    } else {
        return EDPVS_NOTSUPP;
    }

    if (!ifa)
        return EDPVS_NOTEXIST;

    if (!ifa->sa_pool) {
        RTE_LOG(WARNING, SAPOOL, "%s: release addr on IP without pool.",
                __func__);
        inet_addr_ifa_put(ifa);
        return EDPVS_INVAL;
    }

    err = sa_pool_release(sa_pool_hash(ifa->sa_pool, daddr), saddr);
    if (err != EDPVS_OK) {
        inet_addr_ifa_put(ifa);
        return err;
    }

    sa_pool_destroy(ifa);

    inet_addr_ifa_put(ifa);

    return EDPVS_OK;
}

int get_sa_pool_stats(const struct inet_ifaddr *ifa, struct sa_pool_stats *stats)
{
    int hash;
    struct sa_entry_pool *pool;

    if (!ifa || !ifa->sa_pool || !stats)
        return EDPVS_INVAL;

    memset(stats, 0, sizeof(*stats));
    for (hash = 0; hash < ifa->sa_pool->pool_hash_sz; hash++) {
        pool = &ifa->sa_pool->pool_hash[hash];
        assert(pool);

        stats->used_cnt += pool->used_cnt;
        stats->free_cnt += pool->free_cnt;
        stats->miss_cnt += pool->miss_cnt;
    }

    return EDPVS_OK;
}

int sa_pool_init(void)
{
    int shift;
    lcoreid_t cid;
    uint16_t port_base;

    /* enabled lcore should not change after init */
    netif_get_slave_lcores(&sa_nlcore, &sa_lcore_mask);

    /* how many mask bits needed ? */
    for (shift = 0; (0x1<<shift) < sa_nlcore; shift++)
        ;
    if (shift >= 16)
        return EDPVS_INVAL; /* bad config */

    port_base = 0;
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (cid >= 64 || !(sa_lcore_mask & (1L << cid)))
            continue;
        assert(rte_lcore_is_enabled(cid) && cid != rte_get_main_lcore());

        sa_flows[cid].mask = ~((~0x0) << shift);
        sa_flows[cid].lcore = cid;
        sa_flows[cid].port_base = htons(port_base);
        sa_flows[cid].shift = shift;

        port_base++;
    }

    return EDPVS_OK;
}

int sa_pool_term(void)
{
    return EDPVS_OK;
}

/*
 * config file
 */
static void sa_pool_hash_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int size;

    if (!str)
        return;

    size = atoi(str);
    if (size < SAPOOL_MIN_HASH_SZ || size > SAPOOL_MAX_HASH_SZ) {
        RTE_LOG(WARNING, SAPOOL, "%s: invalid pool_hash_size\n", __func__);
    } else {
        sa_pool_hash_size = size;
    }

    FREE_PTR(str);
}

static void sa_pool_flow_enable_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    if (!str)
        return;

    if (!strcasecmp(str, "on"))
        sapool_flow_enable = true;
    if (!strcasecmp(str, "off"))
        sapool_flow_enable = false;
    else
        RTE_LOG(WARNING, SAPOOL, "sapool_filter_enable = %s\n", sapool_flow_enable ? "on" : "off");

    FREE_PTR(str);
}

void install_sa_pool_keywords(void)
{
    install_keyword_root("sa_pool", NULL);
    install_keyword("pool_hash_size", sa_pool_hash_size_handler, KW_TYPE_INIT);
    install_keyword("flow_enable", sa_pool_flow_enable_handler, KW_TYPE_INIT);
}
