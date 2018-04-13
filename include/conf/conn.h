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

#ifndef __DPVS_CONN_CONF_H__
#define __DPVS_CONN_CONF_H__
#include "list.h"
#include "inet.h"

/* How many connections returned at most for one sockopt ctrl msg.
 * Decrease it for saving memory, increase it for better performace.
 */
#define MAX_CTRL_CONN_GET_ENTRIES       1024


enum conn_get_flags {
    GET_IPVS_CONN_FLAG_ALL          = 1,
    GET_IPVS_CONN_FLAG_MORE         = 2,
    GET_IPVS_CONN_FLAG_SPECIFIED    = 4,
    GET_IPVS_CONN_FLAG_TEMPLATE     = 8,
};

enum conn_get_result {
    GET_IPVS_CONN_RESL_OK           = 1,
    GET_IPVS_CONN_RESL_MORE         = 2,
    GET_IPVS_CONN_RESL_FAIL         = 4,
    GET_IPVS_CONN_RESL_NOTEXIST     = 8,
};

enum {
    /* get */
    SOCKOPT_GET_CONN_ALL = 1000,
    SOCKOPT_GET_CONN_SPECIFIED,
};

struct ip_vs_sockpair {
    uint16_t af;
    uint16_t proto;
    __be16 sport;
    __be16 tport;
    __be32 sip;
    __be32 tip;
};

typedef struct ip_vs_sockpair ipvs_sockpair_t;

struct ip_vs_conn_entry {
    uint16_t   af;
    uint16_t   proto;
    __be32      caddr;
    __be32      vaddr;
    __be32      laddr;
    __be32      daddr;
    uint16_t   cport;
    uint16_t   vport;
    uint16_t   lport;
    uint16_t   dport;
    uint32_t   timeout;
    uint8_t    lcoreid;
    char        state[16];
};
typedef struct ip_vs_conn_entry ipvs_conn_entry_t;

struct ip_vs_conn_req {
    uint32_t flag;
    uint32_t whence;
    ipvs_sockpair_t sockpair;
};

struct ip_vs_conn_array {
    uint32_t nconns;
    uint32_t resl;
    uint8_t curcid;
    ipvs_conn_entry_t array[0];
} __attribute__((__packed__));

#endif /* __DPVS_BLKLST_CONF_H__ */
