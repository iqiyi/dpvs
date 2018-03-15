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
/*
 * socket address (or local <ip, port> pair) pool.
 *
 * for multi-core app, the traffic comes back of local initiated
 * connection need reach original CPU core. there are several
 * ways to achieve the goal. one is to calc RSS the same way of
 * NIC to select the currect CPU for connect.
 *
 * the way we use is based on Flow-Director (fdir), allocate
 * local source (e.g., <ip, port>) for each CPU core in advance.
 * and redirect the back traffic to that CPU by fdir. it does not
 * need too many fdir rules, the number of rules can be equal to
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
#include "ctrl.h"
#include "sa_pool.h"
#include "parser/parser.h"
#include "parser/vector.h"

#define MAX_PORT            65536

#define DEF_MIN_PORT        1025
#define DEF_MAX_PORT        65535

#define SAPOOL
#define RTE_LOGTYPE_SAPOOL  RTE_LOGTYPE_USER1

#define MAX_FDIR_PROTO      2

#define SAPOOL_DEF_HASH_SZ  16
#define SAPOOL_MIN_HASH_SZ  1
#define SAPOOL_MAX_HASH_SZ  128

enum {
    SA_F_USED               = 0x01,
};

/**
 * if really need to to save memory, we can;
 * 1. use hlist_head
 * 2. use uint8_t flag
 * 3. remove sa_entry.addr, and get IP from sa_pool->ifa
 * 4. to __packed__ sa_entry.
 * 5. alloc sa_entries[] for 65536/cpu_num only.
 * 6. create sa_entry_pool only if pool_hash hit.
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
    struct sa_entry         sa_entries[MAX_PORT];
    struct list_head        used_enties;
    struct list_head        free_enties;
    /* another way is use total_used/free_cnt in sa_pool,
     * so that we need not travels the hash to get stats.
     * we use cnt here, since we may need per-pool stats. */
    rte_atomic16_t          used_cnt;
    rte_atomic16_t          free_cnt;
    uint32_t                miss_cnt;
};

/* no lock needed because inet_ifaddr.sa_pool[]
 * is per-lcore. */
struct sa_pool {
    struct inet_ifaddr      *ifa;       /* back-pointer */

    uint16_t                low;        /* min port */
    uint16_t                high;       /* max port */
    rte_atomic32_t          refcnt;

    /* hashed pools by dest's <ip/port>. if no dest provided,
     * just use first pool. it's not need create/destroy pool
     * for each dest, that'll be to complicated. */
    struct sa_entry_pool    *pool_hash;
    uint8_t                 pool_hash_sz;

    /* fdir filter ID */
    uint32_t                filter_id[MAX_FDIR_PROTO];
};

struct sa_fdir {
    /* the ports one lcore can use means
     * "(fdir.mask & port) == port_base" */
    uint16_t                mask;       /* filter's port mask */
    lcoreid_t               lcore;
    __be16                  port_base;
    uint16_t                soft_id;    /* current unsed soft-id,
                                           increase after use. */
};

static struct sa_fdir       sa_fdirs[RTE_MAX_LCORE];

static uint8_t              sa_nlcore;
static uint64_t             sa_lcore_mask;

static uint8_t              sa_pool_hash_size   = SAPOOL_DEF_HASH_SZ;

static int __add_del_filter(struct netif_port *dev, lcoreid_t cid,
                            __be32 dip, __be16 dport,
                            uint32_t filter_id[MAX_FDIR_PROTO], bool add)
{
    struct rte_eth_fdir_filter filt[MAX_FDIR_PROTO] = {
        {
            .input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_TCP,
            .input.flow.tcp4_flow.ip.dst_ip = dip,
            .input.flow.tcp4_flow.dst_port = dport,

            .action.behavior = RTE_ETH_FDIR_ACCEPT,
            .action.report_status = RTE_ETH_FDIR_REPORT_ID,
            .soft_id = filter_id[0],
        },
        {
            .input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP,
            .input.flow.udp4_flow.ip.dst_ip = dip,
            .input.flow.udp4_flow.dst_port = dport,

            .action.behavior = RTE_ETH_FDIR_ACCEPT,
            .action.report_status = RTE_ETH_FDIR_REPORT_ID,
            .soft_id = filter_id[1],
        },
    };
    queueid_t queue;
    int err;
    enum rte_filter_op op, rop;
#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    char ipaddr[64];
#endif

    if (dev->netif_ops && dev->netif_ops->op_filter_supported) {
        if (dev->netif_ops->op_filter_supported(dev, RTE_ETH_FILTER_FDIR) < 0) {
            if (dev->nrxq <= 1)
                return EDPVS_OK;
            RTE_LOG(ERR, SAPOOL, "%s: FDIR is not supported by device %s. Only"
                    " single rxq can be configured.\n", __func__, dev->name);
            return EDPVS_NOTSUPP;
        }
    } else {
        RTE_LOG(ERR, SAPOOL, "%s: FDIR support of device %s is not known.\n",
                __func__, dev->name);
        return EDPVS_INVAL;
    }

    err = netif_get_queue(dev, cid, &queue);
    if (err != EDPVS_OK)
        return err;

    filt[0].action.rx_queue = filt[1].action.rx_queue = queue;
    op = add ? RTE_ETH_FILTER_ADD : RTE_ETH_FILTER_DELETE;

    err = netif_fdir_filter_set(dev, op, &filt[0]);
    if (err != EDPVS_OK)
        return err;

    err = netif_fdir_filter_set(dev, op, &filt[1]);
    if (err != EDPVS_OK) {
        rop = add ? RTE_ETH_FILTER_DELETE : RTE_ETH_FILTER_ADD;
        netif_fdir_filter_set(dev, rop, &filt[0]);
        return err;
    }

#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    RTE_LOG(DEBUG, SAPOOL, "FDIR: %s %s TCP/UDP "
            "ip %s port %d (0x%04x) mask 0x%04X queue %d lcore %2d\n",
            add ? "add" : "del", dev->name,
            inet_ntop(AF_INET, &dip, ipaddr, sizeof(ipaddr)) ? : "::",
            ntohs(dport), ntohs(dport), sa_fdirs[cid].mask, queue, cid);
#endif

    return err;
}

static inline int sa_add_filter(struct netif_port *dev, lcoreid_t cid,
                                __be32 dip, __be16 dport,
                                uint32_t filter_id[MAX_FDIR_PROTO])
{
    return  __add_del_filter(dev, cid, dip, dport, filter_id, true);
}

static inline int sa_del_filter(struct netif_port *dev, lcoreid_t cid,
                                __be32 dip, __be16 dport,
                                uint32_t filter_id[MAX_FDIR_PROTO])
{
    return  __add_del_filter(dev, cid, dip, dport, filter_id, false);
}

static int sa_pool_alloc_hash(struct sa_pool *ap, uint8_t hash_sz,
                               const struct sa_fdir *fdir)
{
    int hash;
    struct sa_entry_pool *pool;
    uint32_t port; /* should be u32 or 65535==0 */

    ap->pool_hash = rte_malloc(NULL, sizeof(struct sa_entry_pool) * hash_sz,
                               RTE_CACHE_LINE_SIZE);
    if (!ap->pool_hash)
        return EDPVS_NOMEM;

    ap->pool_hash_sz = hash_sz;

    for (hash = 0; hash < hash_sz; hash++) {
        pool = &ap->pool_hash[hash];

        INIT_LIST_HEAD(&pool->used_enties);
        INIT_LIST_HEAD(&pool->free_enties);

        rte_atomic16_set(&pool->used_cnt, 0);
        rte_atomic16_set(&pool->free_cnt, 0);

        for (port = ap->low; port <= ap->high; port++) {
            struct sa_entry *sa;

            if (fdir->mask &&
                ((uint16_t)port & fdir->mask) != ntohs(fdir->port_base))
                continue;

            sa = &pool->sa_entries[(uint16_t)port];
            sa->addr = ap->ifa->addr;
            sa->port = htons((uint16_t)port);
            list_add_tail(&sa->list, &pool->free_enties);
            rte_atomic16_inc(&pool->free_cnt);
        }
    }

    return EDPVS_OK;
}

static int sa_pool_free_hash(struct sa_pool *ap)
{
    rte_free(ap->pool_hash);
    ap->pool_hash_sz = 0;
    return EDPVS_OK;
}

int sa_pool_create(struct inet_ifaddr *ifa, uint16_t low, uint16_t high)
{
    struct sa_pool *ap;
    int err;
    lcoreid_t cid;

    low = low ? : DEF_MIN_PORT;
    high = high ? : DEF_MAX_PORT;

    if (!ifa || low > high || low == 0 || high >= MAX_PORT) {
        RTE_LOG(ERR, SAPOOL, "%s: bad arguments\n", __func__);
        return EDPVS_INVAL;
    }

    for (cid = 0; cid < RTE_MAX_LCORE; cid++) {
        uint32_t filtids[MAX_FDIR_PROTO];
        struct sa_fdir *fdir = &sa_fdirs[cid];

        /* skip master and unused cores */
        if (cid > 64 || !(sa_lcore_mask & (1L << cid)))
            continue;
        assert(rte_lcore_is_enabled(cid) && cid != rte_get_master_lcore());

        ap = rte_zmalloc(NULL, sizeof(struct sa_pool), 0);
        if (!ap) {
            err = EDPVS_NOMEM;
            goto errout;
        }

        ap->ifa = ifa;
        ap->low = low;
        ap->high = high;
        rte_atomic32_set(&ap->refcnt, 0);

        err = sa_pool_alloc_hash(ap, sa_pool_hash_size, fdir);
        if (err != EDPVS_OK) {
            rte_free(ap);
            goto errout;
        }

        /* if add filter failed, waste some soft-id is acceptable. */
        filtids[0] = fdir->soft_id++;
        filtids[1] = fdir->soft_id++;
        err = sa_add_filter(ifa->idev->dev, cid, ifa->addr.in.s_addr,
                            fdir->port_base, filtids);
        if (err != EDPVS_OK) {
            sa_pool_free_hash(ap);
            rte_free(ap);
            goto errout;
        }
        ap->filter_id[0] = filtids[0];
        ap->filter_id[1] = filtids[1];

        ifa->sa_pools[cid] = ap;
    }

#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    RTE_LOG(DEBUG, SAPOOL, "%s: sa pool created\n", __func__);
#endif
    return EDPVS_OK;

errout:
    sa_pool_destroy(ifa);
    return err;
}

int sa_pool_destroy(struct inet_ifaddr *ifa)
{
    lcoreid_t cid;

    if (!ifa || !ifa->sa_pools)
        return EDPVS_INVAL;

    for (cid = 0; cid < RTE_MAX_LCORE; cid++) {
        struct sa_pool *ap = ifa->sa_pools[cid];
        struct sa_fdir *fdir = &sa_fdirs[cid];

        if (cid > 64 || !(sa_lcore_mask & (1L << cid)))
            continue;
        assert(rte_lcore_is_enabled(cid) && cid != rte_get_master_lcore());

        if (!ap)
            continue;

        if (rte_atomic32_read(&ap->refcnt) != 0) {
            RTE_LOG(WARNING, SAPOOL, "%s: sa pool is inusing\n", __func__);
            return EDPVS_BUSY;
        }

        sa_del_filter(ifa->idev->dev, cid, ifa->addr.in.s_addr,
                      fdir->port_base, ap->filter_id);
        sa_pool_free_hash(ap);
        rte_free(ap);
        ifa->sa_pools[cid] = NULL;
    }

#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    RTE_LOG(DEBUG, SAPOOL, "%s: sa pool destroyed\n", __func__);
#endif
    return EDPVS_OK;
}


/* hash dest's <ip/port>. if no dest provided, just use first pool. */
static inline struct sa_entry_pool *
sa_pool_hash(const struct sa_pool *ap, const struct sockaddr_in *sin)
{
    uint16_t vect[2];
    assert(ap && ap->pool_hash && ap->pool_hash_sz >= 1);

    if (!sin)
        return &ap->pool_hash[0];

    vect[0] = ntohl(sin->sin_addr.s_addr) & 0xffff;
    vect[1] = ntohs(sin->sin_port);

    return &ap->pool_hash[(vect[0] + vect[1]) % ap->pool_hash_sz];
}

/*
 * this API support IPv4 only.
 * sockaddr is not safe use sockaddr_storage if need proto-independent.
 */
static inline int sa_pool_fetch(struct sa_entry_pool *pool,
                                struct sockaddr_in *sin)
{
    struct sa_entry *ent;
#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    char addr[64];
#endif
    assert(pool && sin);

    ent = list_first_entry_or_null(&pool->free_enties, struct sa_entry, list);
    if (!ent) {
#ifdef CONFIG_DPVS_SAPOOL_DEBUG
        RTE_LOG(DEBUG, SAPOOL, "%s: no entry (used/free %d/%d)\n", __func__,
                rte_atomic16_read(&pool->used_cnt),
                rte_atomic16_read(&pool->free_cnt));
#endif
        pool->miss_cnt++;
        return EDPVS_RESOURCE;
    }

    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ent->addr.in.s_addr;
    sin->sin_port = ent->port;

    ent->flags |= SA_F_USED;
    list_move_tail(&ent->list, &pool->used_enties);
    rte_atomic16_inc(&pool->used_cnt);
    rte_atomic16_dec(&pool->free_cnt);

#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    RTE_LOG(DEBUG, SAPOOL, "%s: %s:%d fetched!\n", __func__,
            inet_ntop(AF_INET, &ent->addr.in, addr, sizeof(addr)) ? : NULL,
            ntohs(ent->port));
#endif

    return EDPVS_OK;
}

static inline int sa_pool_release(struct sa_entry_pool *pool,
                                  const struct sockaddr_in *sin)
{
    assert(pool && sin);
    struct sa_entry *ent;
    __be16 port = ntohs(sin->sin_port);
#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    char addr[64];
#endif
    assert(port > 0 && port < MAX_PORT);

    /* it's too slow to traverse the used_enties list
     * (by list_for_each_entry_safe) to find the @entry
     * matchs @sin. */
    ent = &pool->sa_entries[port];
    if (!(ent->flags & SA_F_USED)) {
        RTE_LOG(WARNING, SAPOOL, "%s: port %d not in use !\n", __func__, port);
        return EDPVS_INVAL;
    }

    assert(ent->addr.in.s_addr == sin->sin_addr.s_addr &&
           ent->port == sin->sin_port);

    ent->flags &= (~SA_F_USED);
    list_move_tail(&ent->list, &pool->free_enties);
    rte_atomic16_dec(&pool->used_cnt);
    rte_atomic16_inc(&pool->free_cnt);

#ifdef CONFIG_DPVS_SAPOOL_DEBUG
    RTE_LOG(DEBUG, SAPOOL, "%s: %s:%d released!\n", __func__,
            inet_ntop(AF_INET, &ent->addr.in, addr, sizeof(addr)) ? : NULL,
            ntohs(ent->port));
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
 */
int sa_fetch(struct netif_port *dev, const struct sockaddr_in *daddr,
             struct sockaddr_in *saddr)
{
    struct inet_ifaddr *ifa;
    struct flow4 fl;
    struct route_entry *rt;
    int err;
    assert(saddr);

    if (saddr->sin_addr.s_addr != INADDR_ANY && saddr->sin_port != 0)
        return 0; /* everything is known, why call this function ? */

    /* if source IP is assiged, we can find ifa->this_sa_pool
     * without @daddr and @dev. */
    if (saddr && saddr->sin_addr.s_addr) {
        ifa = inet_addr_ifa_get(AF_INET, dev,
                                (union inet_addr*)&saddr->sin_addr);
        if (!ifa)
            return EDPVS_NOTEXIST;

        if (!ifa->this_sa_pool) {
            RTE_LOG(WARNING, SAPOOL, "%s: fetch addr on IP without pool.",
                    __func__);
            inet_addr_ifa_put(ifa);
            return EDPVS_INVAL;
        }

        err = sa_pool_fetch(sa_pool_hash(ifa->this_sa_pool, daddr), saddr);
        if (err == EDPVS_OK)
            rte_atomic32_inc(&ifa->this_sa_pool->refcnt);
        inet_addr_ifa_put(ifa);
        return err;
    }

    /* try to find source ifa by @dev and @daddr */
    memset(&fl, 0, sizeof(struct flow4));
    fl.oif = dev;
    fl.daddr.s_addr = daddr ? daddr->sin_addr.s_addr : htonl(INADDR_ANY);
    fl.saddr.s_addr = saddr ? saddr->sin_addr.s_addr : htonl(INADDR_ANY);
    rt = route4_output(&fl);
    if (!rt)
        return EDPVS_NOROUTE;;

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

    if (!ifa->this_sa_pool) {
        RTE_LOG(WARNING, SAPOOL, "%s: fetch addr on IP without pool.",
                __func__);
        inet_addr_ifa_put(ifa);
        return EDPVS_INVAL;
    }

    /* do fetch socket address */
    err = sa_pool_fetch(sa_pool_hash(ifa->this_sa_pool, daddr), saddr);
    if (err == EDPVS_OK)
        rte_atomic32_inc(&ifa->this_sa_pool->refcnt);

    inet_addr_ifa_put(ifa);
    return err;
}

int sa_release(const struct netif_port *dev, const struct sockaddr_in *daddr,
               const struct sockaddr_in *saddr)
{
    struct inet_ifaddr *ifa;
    int err;

    if (!saddr)
        return EDPVS_INVAL;

    ifa = inet_addr_ifa_get(AF_INET, dev,
                            (union inet_addr*)&saddr->sin_addr);
    if (!ifa)
        return EDPVS_NOTEXIST;

    if (!ifa->this_sa_pool) {
        RTE_LOG(WARNING, SAPOOL, "%s: release addr on IP without pool.",
                __func__);
        inet_addr_ifa_put(ifa);
        return EDPVS_INVAL;
    }

    err = sa_pool_release(sa_pool_hash(ifa->this_sa_pool, daddr), saddr);
    if (err == EDPVS_OK)
        rte_atomic32_dec(&ifa->this_sa_pool->refcnt);
    inet_addr_ifa_put(ifa);
    return err;
}

int sa_pool_stats(const struct inet_ifaddr *ifa, struct sa_pool_stats *stats)
{
    struct dpvs_msg *req, *reply;
    struct dpvs_multicast_queue *replies = NULL;
    int err;

    memset(stats, 0, sizeof(*stats));

    /*
     * worker need know which ifa's stats to get.
     * but passing @ifa pointer to worker lcores doesn't make sense,
     * note the worker must only access per-lcore data ifa->sa_pools[cid].
     */
    req = msg_make(MSG_TYPE_SAPOOL_STATS, 0, DPVS_MSG_MULTICAST,
                   rte_lcore_id(), sizeof(struct inet_ifaddr *), &ifa);
    if (!req)
        return EDPVS_NOMEM;

    err = multicast_msg_send(req, 0, &replies);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SAPOOL, "%s: mc msg send fail: %s\n", __func__,
                dpvs_strerror(err));
        msg_destroy(&req);
        return err;
    }

    list_for_each_entry(reply, &replies->mq, mq_node) {
        struct sa_pool_stats *st = (struct sa_pool_stats *)reply->data;
        assert(st);

        stats->used_cnt += st->used_cnt;
        stats->free_cnt += st->free_cnt;
        stats->miss_cnt += st->miss_cnt;
    }

    msg_destroy(&req);
    return 0;
}

static int sa_msg_get_stats(struct dpvs_msg *msg)
{
    const struct inet_ifaddr *ifa;
    struct sa_pool_stats *stats;
    struct sa_entry_pool *pool;
    void *ptr;
    int hash;

    assert(msg && msg->len == sizeof(struct inet_ifaddr *));

    ptr = msg->data;
    ifa = *(struct inet_ifaddr **)ptr;

    stats = rte_zmalloc(NULL, sizeof(*stats), 0);
    if (!stats)
        return EDPVS_NOMEM;

    if (!ifa->this_sa_pool)
        goto reply;

    for (hash = 0; hash < ifa->this_sa_pool->pool_hash_sz; hash++) {
        pool = &ifa->this_sa_pool->pool_hash[hash];
        assert(pool);

        stats->used_cnt += rte_atomic16_read(&pool->used_cnt);
        stats->free_cnt += rte_atomic16_read(&pool->free_cnt);
        stats->miss_cnt += pool->miss_cnt;
    }

reply:
    msg->reply.len = sizeof(*stats);
    msg->reply.data = stats;

    return EDPVS_OK;
}

static struct dpvs_msg_type sa_stats_msg = {
    .type           = MSG_TYPE_SAPOOL_STATS,
    .unicast_msg_cb = sa_msg_get_stats,
};

int sa_pool_init(void)
{
    int shift, err;
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
    for (cid = 0; cid < RTE_MAX_LCORE; cid++) {
        if (cid > 64 || !(sa_lcore_mask & (1L << cid)))
            continue;
        assert(rte_lcore_is_enabled(cid) && cid != rte_get_master_lcore());

        sa_fdirs[cid].mask = ~((~0x0) << shift);
        sa_fdirs[cid].lcore = cid;
        sa_fdirs[cid].port_base = htons(port_base);
        sa_fdirs[cid].soft_id = 0;

        port_base++;
    }

    err = msg_type_mc_register(&sa_stats_msg);

    return err;
}

int sa_pool_term(void)
{
    int err;

    err = msg_type_mc_unregister(&sa_stats_msg);

    return err;
}

/*
 * config file
 */
static void sa_pool_hash_size_conf(vector_t tokens)
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

void install_sa_pool_keywords(void)
{
    install_keyword_root("sa_pool", NULL);
    install_keyword("pool_hash_size", sa_pool_hash_size_conf, KW_TYPE_INIT);
}
