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
#include "ipvs/redirect.h"

#define DPVS_REDIRECT_RING_SIZE  4096

/* the bucket size of the global connection redirect hash table */
#define DPVS_CR_TAB_SIZE   DPVS_CONN_TAB_SIZE
#define DPVS_CR_TAB_MASK   DPVS_CONN_TAB_MASK

static struct list_head   *dp_vs_cr_tab;
static rte_spinlock_t      dp_vs_cr_lock[DPVS_CR_TAB_SIZE];
static struct rte_mempool *dp_vs_cr_cache[DPVS_MAX_SOCKET];
#define this_cr_cache      (dp_vs_cr_cache[rte_socket_id()])

static struct rte_ring    *dp_vs_redirect_ring[DPVS_MAX_LCORE][DPVS_MAX_LCORE];

struct dp_vs_redirect *
dp_vs_redirect_alloc(enum dpvs_fwd_mode fwdmode)
{
    struct dp_vs_redirect *r;

    if (fwdmode != DPVS_FWD_MODE_NAT) {
        return NULL;
    }

    if (unlikely(rte_mempool_get(this_cr_cache, (void **)&r) != 0)) {
        RTE_LOG(WARNING, IPVS,
                "%s: no memory for conn redirect\n", __func__);
        return NULL;
    }

    memset(r, 0, sizeof(struct dp_vs_redirect));
    r->redirect_pool = this_cr_cache;

    return r;
}

void dp_vs_redirect_free(struct dp_vs_conn *conn)
{
    if (conn->redirect) {
        rte_mempool_put(this_cr_cache, conn->redirect);
        conn->redirect = NULL;
    }
}

void dp_vs_redirect_init(struct dp_vs_conn *conn)
{
    struct conn_tuple_hash *t = &tuplehash_out(conn);
    struct dp_vs_redirect *r = conn->redirect;

    r->af    = t->af;
    r->proto = t->proto;
    r->saddr = t->saddr;
    r->daddr = t->daddr;
    r->sport = t->sport;
    r->dport = t->dport;
    r->cid   = rte_lcore_id();
}

/**
 * try lookup dp_vs_cr_tab{} by packet tuple
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
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char sbuf[64], dbuf[64];
#endif

    hash = dp_vs_conn_hashkey(af, saddr, sport, daddr, dport, DPVS_CR_TAB_MASK);

    rte_spinlock_lock(&dp_vs_cr_lock[hash]);
    list_for_each_entry(r, &dp_vs_cr_tab[hash], list) {
        if (r->af == af
            && r->proto == proto
            && r->sport == sport
            && r->dport == dport
            && inet_addr_equal(af, &r->saddr, saddr)
            && inet_addr_equal(af, &r->daddr, daddr))
        {
            goto found;
        }
    }
    rte_spinlock_unlock(&dp_vs_cr_lock[hash]);

    return NULL;

found:
    rte_spinlock_unlock(&dp_vs_cr_lock[hash]);

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS, "redirect lookup: [%d -> %d] %s %s:%d -> %s:%d %s \n",
            rte_lcore_id(), r->cid, inet_proto_name(proto),
            inet_ntop(af, saddr, sbuf, sizeof(sbuf)) ? sbuf : "::", ntohs(sport),
            inet_ntop(af, daddr, dbuf, sizeof(dbuf)) ? dbuf : "::", ntohs(dport),
            r ? "hit" : "miss");
#endif

    return r;
}

int dp_vs_redirect_hash(struct dp_vs_conn *conn)
{
    uint32_t hash;
    struct dp_vs_redirect *r = conn->redirect;

    if (unlikely(dp_vs_conn_is_redirect_hashed(conn))) {
        return EDPVS_EXIST;
    }

    hash = dp_vs_conn_hashkey(conn->af,
                    &tuplehash_out(conn).saddr, tuplehash_out(conn).sport,
                    &tuplehash_out(conn).daddr, tuplehash_out(conn).dport,
                    DPVS_CR_TAB_MASK);

    rte_spinlock_lock(&dp_vs_cr_lock[hash]);
    list_add(&r->list, &dp_vs_cr_tab[hash]);
    rte_spinlock_unlock(&dp_vs_cr_lock[hash]);

    dp_vs_conn_set_redirect_hashed(conn);

    return EDPVS_OK;
}

int dp_vs_redirect_unhash(struct dp_vs_conn *conn)
{
    int err;
    uint32_t hash;
    struct dp_vs_redirect *r = conn->redirect;

    if (likely(dp_vs_conn_is_redirect_hashed(conn))) {
        hash = dp_vs_conn_hashkey(r->af,
                                  &r->saddr, r->sport,
                                  &r->daddr, r->dport,
                                  DPVS_CR_TAB_MASK);

        rte_spinlock_lock(&dp_vs_cr_lock[hash]);
        list_del(&r->list);
        rte_spinlock_unlock(&dp_vs_cr_lock[hash]);

        dp_vs_conn_clear_redirect_hashed(conn);
        err = EDPVS_OK;
    } else {
        err = EDPVS_NOTEXIST;
    }

    return err;
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
        RTE_LOG(WARNING, IPVS,
                "%s: [%d] failed to enqueue mbuf to redirect_ring[%d][%d]\n",
                __func__, cid, peer_cid, cid);
        return INET_DROP;
    }

    return INET_STOLEN;
}

void dp_vs_redirect_ring_proc(struct netif_queue_conf *qconf, lcoreid_t cid)
{
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    uint16_t nb_rb;
    lcoreid_t peer_cid;

    cid = rte_lcore_id();

    for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
        if (dp_vs_redirect_ring[cid][peer_cid]) {
            nb_rb = rte_ring_dequeue_burst(dp_vs_redirect_ring[cid][peer_cid],
                                           (void**)mbufs,
                                           NETIF_MAX_PKT_BURST, NULL);
            if (nb_rb > 0) {
                lcore_process_packets(qconf, mbufs, cid, nb_rb, 0);
            }
        }
    }
}

static int dp_vs_redirect_table_create(void)
{
    int i;
    char poolname[32];

    /*
     * allocate redirect cache on each NUMA socket and its size is
     * same as conn_pool_size
     */
    for (i = 0; i < get_numa_nodes(); i++) {
        snprintf(poolname, sizeof(poolname), "dp_vs_redirect_%d", i);
        dp_vs_cr_cache[i] =
            rte_mempool_create(poolname,
                               dp_vs_conn_pool_size(),
                               sizeof(struct dp_vs_redirect),
                               dp_vs_conn_pool_cache_size(),
                               0, NULL, NULL, NULL, NULL,
                               i, 0);
        if (!dp_vs_cr_cache[i]) {
            return EDPVS_NOMEM;
        }
    }

    /* allocate the global redirect hash table, per socket? */
    dp_vs_cr_tab =
        rte_malloc_socket(NULL, sizeof(struct list_head ) * DPVS_CR_TAB_SIZE,
                          RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!dp_vs_cr_tab) {
        return EDPVS_NOMEM;
    }

    /* init the global redirect hash table */
    for (i = 0; i < DPVS_CR_TAB_SIZE; i++) {
        INIT_LIST_HEAD(&dp_vs_cr_tab[i]);
        rte_spinlock_init(&dp_vs_cr_lock[i]);
    }

    return EDPVS_OK;
}

static void dp_vs_redirect_table_free(void)
{
    int i;

    for (i = 0; i < get_numa_nodes(); i++) {
        rte_mempool_free(dp_vs_cr_cache[i]);
    }

    /* release the global redirect hash table */
    rte_free(dp_vs_cr_tab);
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
        if (cid == rte_get_master_lcore() || !rte_lcore_is_enabled(cid)) {
            continue;
        }

        for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
            if (!rte_lcore_is_enabled(peer_cid)
                || peer_cid == rte_get_master_lcore()
                || cid == peer_cid)
            {
                continue;
            }

            snprintf(name_buf, RTE_RING_NAMESIZE,
                     "dp_vs_redirect_ring[%d[%d]", cid, peer_cid);

            dp_vs_redirect_ring[cid][peer_cid] =
                rte_ring_create(name_buf, DPVS_REDIRECT_RING_SIZE, socket_id,
                                RING_F_SP_ENQ | RING_F_SC_DEQ);

            if (!dp_vs_redirect_ring[cid][peer_cid]) {
                RTE_LOG(WARNING, IPVS,
                        "%s: failed to create redirect_ring[%d][%d]\n",
                        __func__, cid, peer_cid);
                return EDPVS_NOMEM;
            } else {
                RTE_LOG(WARNING, IPVS,
                        "%s: created redirect_ring[%d][%d]\n",
                        __func__, cid, peer_cid);
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

    err = dp_vs_redirect_ring_create();
    if (err != EDPVS_OK) {
        return err;
    }

    return dp_vs_redirect_table_create();
}

int dp_vs_redirects_term(void)
{
    dp_vs_redirect_ring_free();
    dp_vs_redirect_table_free();

    return EDPVS_OK;
}
