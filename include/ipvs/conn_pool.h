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
#ifndef __DPVS_CONN_POOL_H__
#define __DPVS_CONN_POOL_H__
#include <stdint.h>
#include "conf/common.h"
#include "ipvs/conn.h"

#define DPVS_CONN_TBL_BITS          20
#define DPVS_CONN_TBL_SIZE          (1 << DPVS_CONN_TBL_BITS)
#define DPVS_CONN_TBL_MASK          (DPVS_CONN_TBL_SIZE - 1)

/*
 * per-lcore dp_vs_conn{} hash table.
 */
RTE_DECLARE_PER_LCORE(struct list_head *, dp_vs_conn_tbl);
#define this_conn_tbl   (RTE_PER_LCORE(dp_vs_conn_tbl))

#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
static RTE_DEFINE_PER_LCORE(rte_spinlock_t, dp_vs_conn_lock);
#define this_conn_lock  (RTE_PER_LCORE(dp_vs_conn_lock))
#endif

extern int      conn_init_timeout;
extern bool     conn_expire_quiescent_template;
extern bool     dp_vs_redirect_disable;

extern uint32_t          dp_vs_conn_rnd; /* hash random */
extern struct list_head *dp_vs_ct_tbl;
extern rte_spinlock_t    dp_vs_ct_lock;

struct dp_vs_conn *dp_vs_conn_alloc(enum dpvs_fwd_mode fwdmode,
    uint32_t flags);
void dp_vs_conn_free(struct dp_vs_conn *conn);
int dp_vs_conn_init(void);
int dp_vs_conn_term(void);

int dp_vs_conn_pool_size(void);
int dp_vs_conn_pool_cache_size(void);
void ipvs_conn_keyword_value_init(void);
void install_ipvs_conn_keywords(void);


#endif /* __DPVS_CONN_POOL_H__ */
