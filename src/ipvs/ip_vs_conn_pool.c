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
#include "list.h"
#include "dpdk.h"
#include "parser/parser.h"
#include "ipvs/xmit.h"
#include "ipvs/conn.h"
#include "ipvs/conn_pool.h"
#include "ipvs/redirect.h"

/* too big ? adjust according to free mem ?*/
#define DPVS_CONN_POOL_SIZE_DEF     2097152
#define DPVS_CONN_POOL_SIZE_MIN     65536
#define DPVS_CONN_CACHE_SIZE_DEF    256
#define DPVS_CONN_INIT_TIMEOUT_DEF  3   /* sec */

static int conn_pool_size  = DPVS_CONN_POOL_SIZE_DEF;
static int conn_pool_cache = DPVS_CONN_CACHE_SIZE_DEF;

/* memory pool for dpvs connections */
static struct rte_mempool *dp_vs_conn_cache[DPVS_MAX_SOCKET];
static RTE_DEFINE_PER_LCORE(uint32_t, dp_vs_conn_count);

#define this_conn_count    (RTE_PER_LCORE(dp_vs_conn_count))
#define this_conn_cache    (dp_vs_conn_cache[rte_socket_id()])

/* dpvs connection hash table */
RTE_DEFINE_PER_LCORE(struct list_head *, dp_vs_conn_tbl);

int  conn_init_timeout = DPVS_CONN_INIT_TIMEOUT_DEF;
bool conn_expire_quiescent_template = false;
bool dp_vs_redirect_disable = true;

/* global connection template table */
struct list_head *dp_vs_ct_tbl;
rte_spinlock_t    dp_vs_ct_lock;

uint32_t dp_vs_conn_rnd; /* hash random */

struct dp_vs_conn *dp_vs_conn_alloc(enum dpvs_fwd_mode fwdmode,
                                    uint32_t flags)
{
    struct dp_vs_conn *conn;
    struct dp_vs_redirect *r = NULL;

    if (unlikely(rte_mempool_get(this_conn_cache, (void **)&conn) != 0)) {
        RTE_LOG(ERR, IPVS, "%s: no memory for connection\n", __func__);
        return NULL;
    }

    memset(conn, 0, sizeof(struct dp_vs_conn));
    conn->connpool = this_conn_cache;
    this_conn_count++;

    /* no need to create redirect for the global template connection */
    if (likely((flags & DPVS_CONN_F_TEMPLATE) == 0))
        r = dp_vs_redirect_alloc(fwdmode);

     conn->redirect = r;

    return conn;
}

void dp_vs_conn_free(struct dp_vs_conn *conn)
{
    if (!conn)
        return;

    dp_vs_redirect_free(conn);

    rte_mempool_put(conn->connpool, conn);
    this_conn_count--;
}

static int conn_init_lcore(void *arg)
{
    int i;

    if (!rte_lcore_is_enabled(rte_lcore_id()))
        return EDPVS_DISABLED;

    if (netif_lcore_is_idle(rte_lcore_id()))
        return EDPVS_IDLE;

    this_conn_tbl = rte_malloc_socket(NULL,
                        sizeof(struct list_head) * DPVS_CONN_TBL_SIZE,
                        RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!this_conn_tbl)
        return EDPVS_NOMEM;

    for (i = 0; i < DPVS_CONN_TBL_SIZE; i++)
        INIT_LIST_HEAD(&this_conn_tbl[i]);

#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_init(&this_conn_lock);
#endif
    this_conn_count = 0;

    return EDPVS_OK;
}

static int conn_term_lcore(void *arg)
{
    if (!rte_lcore_is_enabled(rte_lcore_id()))
        return EDPVS_DISABLED;

    dp_vs_conn_flush();

    if (this_conn_tbl) {
        rte_free(this_conn_tbl);
        this_conn_tbl = NULL;
    }

    return EDPVS_OK;
}

int dp_vs_conn_init(void)
{
    int i, err;
    lcoreid_t lcore;
    char poolname[32];

    /* init connection template table */
    dp_vs_ct_tbl = rte_malloc_socket(NULL, sizeof(struct list_head) * DPVS_CONN_TBL_SIZE,
            RTE_CACHE_LINE_SIZE, rte_socket_id());

    for (i = 0; i < DPVS_CONN_TBL_SIZE; i++)
        INIT_LIST_HEAD(&dp_vs_ct_tbl[i]);
    rte_spinlock_init(&dp_vs_ct_lock);

    /*
     * unlike linux per_cpu() which can assign CPU number,
     * RTE_PER_LCORE() can only access own instances.
     * it make codes looks strange.
     */
    rte_eal_mp_remote_launch(conn_init_lcore, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if ((err = rte_eal_wait_lcore(lcore)) < 0) {
            RTE_LOG(WARNING, IPVS, "%s: lcore %d: %s.\n",
                    __func__, lcore, dpvs_strerror(err));
        }
    }

    conn_ctrl_init();

    /* connection cache on each NUMA socket */
    for (i = 0; i < get_numa_nodes(); i++) {
        snprintf(poolname, sizeof(poolname), "dp_vs_conn_%d", i);
        dp_vs_conn_cache[i] = rte_mempool_create(poolname,
                                    conn_pool_size,
                                    sizeof(struct dp_vs_conn),
                                    conn_pool_cache,
                                    0, NULL, NULL, NULL, NULL,
                                    i, 0);
        if (!dp_vs_conn_cache[i]) {
            err = EDPVS_NOMEM;
            goto cleanup;
        }
    }

    dp_vs_conn_rnd = (uint32_t)random();

    return EDPVS_OK;

cleanup:
    dp_vs_conn_term();
    return err;
}

int dp_vs_conn_term(void)
{
    lcoreid_t lcore;

    /* no API opposite to rte_mempool_create() */

    rte_eal_mp_remote_launch(conn_term_lcore, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        rte_eal_wait_lcore(lcore);
    }

    conn_ctrl_term();

    return EDPVS_OK;
}

int dp_vs_conn_pool_size(void)
{
    return conn_pool_size;
}

int dp_vs_conn_pool_cache_size(void)
{
    return conn_pool_cache;
}

static void conn_pool_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int pool_size;

    assert(str);

    pool_size = atoi(str);

    if (pool_size < DPVS_CONN_POOL_SIZE_MIN) {
        RTE_LOG(WARNING, IPVS, "invalid conn_pool_size %s, using default %d\n",
                str, DPVS_CONN_POOL_SIZE_DEF);
        conn_pool_size = DPVS_CONN_POOL_SIZE_DEF;
    } else {
        is_power2(pool_size, 0, &pool_size);
        RTE_LOG(INFO, IPVS, "conn_pool_size = %d (round to 2^n)\n", pool_size);
        conn_pool_size = pool_size;
    }

    FREE_PTR(str);
}

static void conn_pool_cache_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int pool_cache;

    assert(str);

    if ((pool_cache = atoi(str)) > 0) {
        is_power2(pool_cache, 0, &pool_cache);
        RTE_LOG(INFO, IPVS, "conn_pool_cache = %d (round to 2^n)\n", pool_cache);
        conn_pool_cache = pool_cache;
    } else {
        RTE_LOG(WARNING, IPVS, "invalid conn_pool_cache %s, using default %d\n",
                str, DPVS_CONN_CACHE_SIZE_DEF);
        conn_pool_cache = DPVS_CONN_CACHE_SIZE_DEF;
    }

    FREE_PTR(str);
}

static void conn_init_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int init_timeout;

    assert(str);

    init_timeout = atoi(str);

    if (init_timeout > IPVS_TIMEOUT_MIN && init_timeout < IPVS_TIMEOUT_MAX) {
        RTE_LOG(INFO, IPVS, "conn_init_timeout = %d\n", init_timeout);
        conn_init_timeout = init_timeout;
    } else {
        RTE_LOG(WARNING, IPVS, "invalid conn_init_timeout %s, using default %d\n",
                str, DPVS_CONN_INIT_TIMEOUT_DEF);
        conn_init_timeout = DPVS_CONN_INIT_TIMEOUT_DEF;
    }

    FREE_PTR(str);
}

static void conn_expire_quiscent_template_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "conn_expire_quiescent_template ON\n");
    conn_expire_quiescent_template = true;
}

static void conn_redirect_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    assert(str);

    if (strcasecmp(str, "on") == 0)
        dp_vs_redirect_disable  = false;
    else if (strcasecmp(str, "off") == 0)
        dp_vs_redirect_disable  = true;
    else
        RTE_LOG(WARNING, IPVS, "invalid conn:redirect %s\n", str);

    RTE_LOG(INFO, IPVS, "conn:redirect = %s\n", dp_vs_redirect_disable ? "off" : "on");

    FREE_PTR(str);
}

void ipvs_conn_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        conn_pool_size = DPVS_CONN_POOL_SIZE_DEF;
        conn_pool_cache = DPVS_CONN_CACHE_SIZE_DEF;
        dp_vs_redirect_disable = true;
    }
    /* KW_TYPE_NORMAL keyword */
    conn_init_timeout = DPVS_CONN_INIT_TIMEOUT_DEF;
    conn_expire_quiescent_template = false;
}

void install_ipvs_conn_keywords(void)
{
    install_sublevel();
    install_keyword("conn_pool_size", conn_pool_size_handler, KW_TYPE_INIT);
    install_keyword("conn_pool_cache", conn_pool_cache_handler, KW_TYPE_INIT);
    install_keyword("conn_init_timeout", conn_init_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("expire_quiescent_template", conn_expire_quiscent_template_handler,
            KW_TYPE_NORMAL);
    install_keyword("redirect", conn_redirect_handler, KW_TYPE_INIT);
    install_xmit_keywords();
    install_sublevel_end();
}
