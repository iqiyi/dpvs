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
#ifndef __DPVS_PROXY_PROTOCOL_H__
#define __DPVS_PROXY_PROTOCOL_H__

#include "conf/pphdr.h"
#include "conf/common.h"
#include "ipvs/conn.h"

/**************************** prototypes ******************************/

int dp_vs_pphdr_inbound(struct rte_mbuf *mbuf, struct dp_vs_conn *conn);
int dp_vs_pphdr_outbound(struct rte_mbuf *mbuf, struct dp_vs_conn *conn);

#endif /* __DPVS_PROXY_PROTOCOL_H__ */
