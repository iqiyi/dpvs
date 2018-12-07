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

#ifndef __DPVS_ACL_CONF_H__
#define __DPVS_ACL_CONF_H__

#include <net/if.h>

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

// for 'get'
struct dp_vs_acl_entry {
    int                    af;
    struct inet_addr_range srange;
    struct inet_addr_range drange;

    int                    rule;       /* deny | permit */
    int                    max_conn;   /* maximum connections */
    uint32_t               curr_conn;  /* current connection */
};

struct dp_vs_get_acls {
    /* for get */
    uint32_t               num_acls;
    struct dp_vs_acl_entry entrytable[0];
};

struct dp_vs_acl_conf {
    /* identify service */
    int                    af;
    uint8_t                proto;
    union inet_addr        vaddr;
    uint16_t               vport;
    uint32_t               fwmark;

    /* identify match */
    char                   m_srange[256];
    char                   m_drange[256];
    char                   iifname[IFNAMSIZ];
    char                   oifname[IFNAMSIZ];

    /* identify acl  */
    int                    rule;         /* deny | permit */
    int                    max_conn;     /* maximum connections */
    char                   srange[256];
    char                   drange[256];

    /* for get */
    uint32_t               num_acls;
    struct dp_vs_acl_entry acls[0];
};

#endif /* ifndef __DPVS_ACL_CONF_H__ */
