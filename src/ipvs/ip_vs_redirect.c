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
#include "ipvs/redirect.h"

#define DPVS_REDIRECT_RING_SIZE  2048

#define DPVS_CR_TBL_BITS   20
#define DPVS_CR_TBL_SIZE   (1 << DPVS_CR_TBL_BITS)
#define DPVS_CR_TBL_MASK   (DPVS_CR_TBL_SIZE - 1)

static struct list_head   *dp_vs_cr_tbl;
static rte_spinlock_t      dp_vs_cr_lock[DPVS_CR_TBL_SIZE];
static struct rte_mempool *dp_vs_cr_cache[DPVS_MAX_SOCKET];
#define this_cr_cache      (dp_vs_cr_cache[rte_socket_id()])

static struct rte_ring    *dp_vs_redirect_ring[DPVS_MAX_LCORE][DPVS_MAX_LCORE];

#ifdef CONFIG_DPVS_IPVS_DEBUG
static inline void
dp_vs_redirect_show(struct dp_vs_redirect *r, const char *action)
{
    char sbuf[64], dbuf[64];

    RTE_LOG(DEBUG, IPVS, "[%d] redirect %s: [%d] %s %s/%d -> %s/%d\n",
            rte_lcore_id(), action, r->cid,
            inet_proto_name(r->proto),
            inet_ntop(r->af, &r->saddr, sbuf, sizeof(sbuf)) ? sbuf : "::",
            ntohs(r->sport),
            inet_ntop(r->af, &r->daddr, dbuf, sizeof(dbuf)) ? dbuf : "::",
            ntohs(r->dport));
}
#endif

struct dp_vs_redirect *
dp_vs_redirect_alloc(enum dpvs_fwd_mode fwdmode)
{
    struct dp_vs_redirect *r;

    if (dp_vs_redirect_disable) {
        return NULL;
    }

    /*
     * Currently, IPv6 support has the below issues.
     * a) Fdir IPv6 rules fail to be created with "perfect" mode, but can be
     * created with "signature" mode.
     *
     * b) In full-nat mode, the packets from incoming direction and outgoing
     *   direction are dispatched to the different cores so the service is
     *   broken.
     *
     * The solutuion is to use decentralized packet dispatch for the symemtric
     * service modes, full-nat/snat/nat before issue a) is fixed.
     */
    if (fwdmode != DPVS_FWD_MODE_FNAT
        && fwdmode != DPVS_FWD_MODE_SNAT
        && fwdmode != DPVS_FWD_MODE_NAT) {
        return NULL;
    }

    if (unlikely(rte_mempool_get(this_cr_cache, (void **)&r) != 0)) {
        RTE_LOG(WARNING, IPVS,
                "%s: no memory for redirect\n", __func__);
        return NULL;
    }

    memset(r, 0, sizeof(struct dp_vs_redirect));
    r->redirect_pool = this_cr_cache;

    return r;
}

void dp_vs_redirect_free(struct dp_vs_conn *conn)
{
    if (conn->redirect) {
#ifdef CONFIG_DPVS_IPVS_DEBUG
        dp_vs_redirect_show(conn->redirect, "free");
#endif
        rte_mempool_put(this_cr_cache, conn->redirect);
        conn->redirect = NULL;
    }
}

void dp_vs_redirect_hash(struct dp_vs_conn *conn)
{
    uint32_t hash;
    struct dp_vs_redirect *r = conn->redirect;

    if (!r || unlikely(dp_vs_conn_is_redirect_hashed(conn))) {
        return;
    }

    hash = dp_vs_conn_hashkey(r->af, &r->saddr, r->sport,
            &r->daddr, r->dport, DPVS_CR_TBL_MASK);

    rte_spinlock_lock(&dp_vs_cr_lock[hash]);
    list_add(&r->list, &dp_vs_cr_tbl[hash]);
    rte_spinlock_unlock(&dp_vs_cr_lock[hash]);

    dp_vs_conn_set_redirect_hashed(conn);
}

void dp_vs_redirect_unhash(struct dp_vs_conn *conn)
{
    uint32_t hash;
    struct dp_vs_redirect *r = conn->redirect;

    if (r && likely(dp_vs_conn_is_redirect_hashed(conn))) {
        hash = dp_vs_conn_hashkey(r->af, &r->saddr, r->sport,
                &r->daddr, r->dport, DPVS_CR_TBL_MASK);

        rte_spinlock_lock(&dp_vs_cr_lock[hash]);
        list_del(&r->list);
        rte_spinlock_unlock(&dp_vs_cr_lock[hash]);

        dp_vs_conn_clear_redirect_hashed(conn);
    }
}

void dp_vs_redirect_init(struct dp_vs_conn *conn)
{
    enum dpvs_fwd_mode fm = conn->dest->fwdmode;
    struct conn_tuple_hash *t = &tuplehash_out(conn);
    struct dp_vs_redirect *r = conn->redirect;

    if (!r) {
        return;
    }

    switch (fm) {
    case DPVS_FWD_MODE_FNAT:
    case DPVS_FWD_MODE_NAT:
        t = &tuplehash_out(conn);
        break;

    case DPVS_FWD_MODE_SNAT:
        t = &tuplehash_in(conn);
        break;

    default:
        RTE_LOG(ERR, IPVS,
                "%s: no redirect created for fwd mode %d\n",
                __func__, fm);
        return;
    }

    r->af    = t->af;
    r->proto = t->proto;
    r->saddr = t->saddr;
    r->daddr = t->daddr;
    r->sport = t->sport;
    r->dport = t->dport;
    r->cid   = rte_lcore_id();

#ifdef CONFIG_DPVS_IPVS_DEBUG
    dp_vs_redirect_show(r, "init");
#endif
}

/**
 * try lookup dp_vs_cr_tbl{} by packet tuple
 *
 *  <af, proto, saddr, sport, daddr, dport>.
 *
 * return r if found or NULL if not exist.
 */
struct dp_vs_redirect *
dp_vs_redirect_get(int af, uint16_t proto,
    const union inet_addr *saddr, const union inet_addr *daddr,
    uint16_t sport, uint16_t dport)
{
    uint32_t hash;
    struct dp_vs_redirect *r;

    if (dp_vs_redirect_disable) {
        return NULL;
    }

    hash = dp_vs_conn_hashkey(af, saddr, sport, daddr, dport, DPVS_CR_TBL_MASK);

    rte_spinlock_lock(&dp_vs_cr_lock[hash]);
    list_for_each_entry(r, &dp_vs_cr_tbl[hash], list) {
        if (r->af == af
            && r->proto == proto
            && r->sport == sport
            && r->dport == dport
            && inet_addr_equal(af, &r->saddr, saddr)
            && inet_addr_equal(af, &r->daddr, daddr)) {
            goto found;
        }
    }
    rte_spinlock_unlock(&dp_vs_cr_lock[hash]);

    return NULL;

found:
    rte_spinlock_unlock(&dp_vs_cr_lock[hash]);

#ifdef CONFIG_DPVS_IPVS_DEBUG
    dp_vs_redirect_show(r, "get");
#endif

    return r;
}

/**
 * Forward the packet to the found redirect owner core.
 */
int dp_vs_redirect_pkt(struct rte_mbuf *mbuf, lcoreid_t peer_cid)
{
    lcoreid_t cid = rte_lcore_id();
    int ret;

    ret = rte_ring_enqueue(dp_vs_redirect_ring[peer_cid][cid], mbuf);
    if (ret < 0) {
        RTE_LOG(ERR, IPVS,
                "%s: [%d] failed to enqueue mbuf to redirect_ring[%d][%d]\n",
                __func__, cid, peer_cid, cid);
        return INET_DROP;
    }

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS,
            "%s: [%d] enqueued mbuf to redirect_ring[%d][%d]\n",
            __func__, cid, peer_cid, cid);
#endif

    return INET_STOLEN;
}

void dp_vs_redirect_ring_proc(lcoreid_t cid)
{
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    uint16_t nb_rb;
    lcoreid_t peer_cid;

    if (dp_vs_redirect_disable) {
        return;
    }

    cid = rte_lcore_id();

    for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
        if (dp_vs_redirect_ring[cid][peer_cid]) {
            nb_rb = rte_ring_dequeue_burst(dp_vs_redirect_ring[cid][peer_cid],
                                           (void**)mbufs,
                                           NETIF_MAX_PKT_BURST, NULL);
            if (nb_rb > 0) {
                lcore_process_packets(mbufs, cid, nb_rb, 1);
            }
        }
    }
}

/*
 * allocate redirect cache on each NUMA socket and its size is
 * same as conn_pool_size
 */
static int dp_vs_redirect_cache_alloc(void)
{
    int i;
    char pool_name[32];

    for (i = 0; i < get_numa_nodes(); i++) {
        snprintf(pool_name, sizeof(pool_name), "dp_vs_redirect_%d", i);

        dp_vs_cr_cache[i] =
            rte_mempool_create(pool_name,
                               dp_vs_conn_pool_size(),
                               sizeof(struct dp_vs_redirect),
                               dp_vs_conn_pool_cache_size(),
                               0, NULL, NULL, NULL, NULL,
                               i, 0);

        if (!dp_vs_cr_cache[i]) {
            return EDPVS_NOMEM;
        }
    }

    return EDPVS_OK;
}

static void dp_vs_redirect_cache_free(void)
{
    int i;

    for (i = 0; i < get_numa_nodes(); i++) {
        rte_mempool_free(dp_vs_cr_cache[i]);
    }
}

static int dp_vs_redirect_table_create(void)
{
    int i;

    if (dp_vs_redirect_cache_alloc() != EDPVS_OK) {
        goto cache_free;
    }

    /* allocate the global redirect hash table, per socket? */
    dp_vs_cr_tbl =
        rte_malloc(NULL, sizeof(struct list_head ) * DPVS_CR_TBL_SIZE,
                          RTE_CACHE_LINE_SIZE);
    if (!dp_vs_cr_tbl) {
        goto cache_free;
    }

    /* init the global redirect hash table */
    for (i = 0; i < DPVS_CR_TBL_SIZE; i++) {
        INIT_LIST_HEAD(&dp_vs_cr_tbl[i]);
        rte_spinlock_init(&dp_vs_cr_lock[i]);
    }

    return EDPVS_OK;

cache_free:
    dp_vs_redirect_cache_free();
    return EDPVS_NOMEM;
}

static void dp_vs_redirect_table_free(void)
{
    dp_vs_redirect_cache_free();

    /* release the global redirect hash table */
    if (dp_vs_cr_tbl) {
        rte_free(dp_vs_cr_tbl);
    }
}

/*
 * Each lcore allocates redirect rings with the other lcores espectively.
 */
static int dp_vs_redirect_ring_create(void)
{
    char name_buf[RTE_RING_NAMESIZE];
    int socket_id;
    lcoreid_t cid, peer_cid;

    socket_id = rte_socket_id();

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!netif_lcore_is_fwd_worker(cid)) {
            continue;
        }

        for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
            if (!netif_lcore_is_fwd_worker(peer_cid)
                || cid == peer_cid) {
                continue;
            }

            snprintf(name_buf, RTE_RING_NAMESIZE,
                     "dp_vs_redirect_ring[%d[%d]", cid, peer_cid);

            dp_vs_redirect_ring[cid][peer_cid] =
                rte_ring_create(name_buf, DPVS_REDIRECT_RING_SIZE, socket_id,
                                RING_F_SP_ENQ | RING_F_SC_DEQ);

            if (!dp_vs_redirect_ring[cid][peer_cid]) {
                RTE_LOG(ERR, IPVS,
                        "%s: failed to create redirect_ring[%d][%d]\n",
                        __func__, cid, peer_cid);
                return EDPVS_NOMEM;
            }
        }
    }

    return EDPVS_OK;
}

static void dp_vs_redirect_ring_free(void)
{
    lcoreid_t cid, peer_cid;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
            rte_ring_free(dp_vs_redirect_ring[cid][peer_cid]);
        }
    }
}

int dp_vs_redirects_init(void)
{
    int err;

    if (dp_vs_redirect_disable) {
        return EDPVS_OK;
    }

    err = dp_vs_redirect_ring_create();
    if (err != EDPVS_OK) {
        return err;
    }

    return dp_vs_redirect_table_create();
}

int dp_vs_redirects_term(void)
{
    if (dp_vs_redirect_disable) {
        return EDPVS_OK;
    }

    dp_vs_redirect_ring_free();
    dp_vs_redirect_table_free();

    return EDPVS_OK;
}
