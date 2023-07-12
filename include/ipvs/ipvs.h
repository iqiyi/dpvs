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
#ifndef __DPVS_IPVS_H__
#define __DPVS_IPVS_H__
#include "conf/common.h"
#include "inet.h"
#include "ipvs/service.h"

#ifndef IPVS
#define IPVS
#define RTE_LOGTYPE_IPVS    RTE_LOGTYPE_USER1
#endif

#define IPVS_TIMEOUT_MIN    0
#define IPVS_TIMEOUT_MAX    31536000 /* one year */

struct dp_vs_iphdr {
    int             af;
    int             len;
    uint8_t         proto;
    union inet_addr saddr;
    union inet_addr daddr;
};

/* for sequence number adjusting */
struct dp_vs_seq {
    uint32_t        isn;
    uint32_t        delta;
    uint32_t        fdata_seq;
    uint32_t        prev_delta;
};

int dp_vs_init(void);
int dp_vs_term(void);

struct dp_vs_service;

struct dp_vs_conn *dp_vs_schedule(struct dp_vs_service *svc,
                                  const struct dp_vs_iphdr *iph,
                                  struct rte_mbuf *mbuf,
                                  bool is_synproxy_on);

#endif /* __DPVS_IPVS_H__ */
