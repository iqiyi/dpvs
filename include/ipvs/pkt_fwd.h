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
#ifndef __DPVS_PKT_FWD__H__
#define __DPVS_PKT_FWD_H__

#include "common.h"
#include "dpdk.h"
#include "netif.h"

void dp_vs_pkt_fwd_ring_proc(struct netif_queue_conf *qconf, lcoreid_t cid);
int dp_vs_pkt_fwd(struct rte_mbuf *mbuf, lcoreid_t peer_cid);
int dp_vs_pkt_fwd_init(void);
int dp_vs_pkt_fwd_term(void);

#endif /* __DPVS_PKT_FWD_H__ */
