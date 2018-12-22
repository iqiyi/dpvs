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

#ifndef __DPVS_ACL_H__
#define __DPVS_ACL_H__

#include <net/if.h>
#include "common.h"
#include "inet.h"
#include "list.h"

#define IP_VS_ACL_PERMIT        1
#define IP_VS_ACL_DENY          0
#define IP_VS_ACL_PERMIT_ALL    1
#define IP_VS_ACL_DENY_ALL      0

enum {
    // set
    SOCKOPT_SET_ACL_ADD = 2000,
    SOCKOPT_SET_ACL_DEL,
    SOCKOPT_SET_ACL_FLUSH,
    // get
    SOCKOPT_GET_ACL_ALL,
};

enum DP_VS_ACL_FIND_TYPE {
    DP_VS_ACL_ADD,
    DP_VS_ACL_DEL,
};

#define DP_VS_MATCH_ACL_NOTHASHED     0x0000
#define DP_VS_MATCH_ACL_HASHED        0x0001

struct dp_vs_flow_addr {
    int                    af;
    union inet_addr        addr;
};

struct dp_vs_acl_flow {
    struct dp_vs_flow_addr saddr;
    __be16                 sport;
    struct dp_vs_flow_addr daddr;
    __be16                 dport;
};

struct dp_vs_acl_addr {
    int                    af;
    union inet_addr        addr;
    __be16                 min_port;
    __be16                 max_port;
};

// for 'get'
struct dp_vs_acl_entry {
    uint8_t                rule;       /* deny | permit */
    uint32_t               max_conn;   /* maximum connections */
    uint32_t               p_conn;     /* permitted connections */
    uint32_t               d_conn;     /* denied connections */

    struct dp_vs_acl_addr  saddr;
    struct dp_vs_acl_addr  daddr;
};

/* for get */
struct dp_vs_get_acls {
    uint32_t               num_acls;
    struct dp_vs_acl_entry entrytable[0];
};

struct dp_vs_acl {
    uint8_t                rule;       /* deny | permit */
    uint32_t               max_conn;   /* maximum connections */
    uint32_t               p_conn;     /* permitted connections */
    uint32_t               d_conn;     /* denied connections */

    struct dp_vs_acl_addr  saddr;
    struct dp_vs_acl_addr  daddr;

    struct list_head       list;
};

struct dp_vs_acl_conf {
    /* match used for identify service */
    int                    af;
    uint8_t                proto;
    char                   m_srange[256];
    char                   m_drange[256];
    char                   iifname[IFNAMSIZ];
    char                   oifname[IFNAMSIZ];

    /* identify acl  */
    int                    rule;       /* deny | permit */
    uint32_t               max_conn;   /* maximum connections */
    char                   srange[256];
    char                   drange[256];
};

int dp_vs_acl_init(void);
int dp_vs_acl_term(void);
int dp_vs_acl_verdict(struct dp_vs_acl_flow *, struct dp_vs_service *);
int dp_vs_acl_flush(struct dp_vs_service *svc);
void print_acl_verdict_result(int verdict);

#endif /* ifndef __DPVS_ACL_H__ */
