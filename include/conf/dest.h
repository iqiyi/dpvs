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
#ifndef __DPVS_DEST_CONF_H__
#define __DPVS_DEST_CONF_H__

#include "conf/match.h"
#include "conf/conn.h"

/*
 * DPVS_FWD_XXX should always be the same with IP_VS_CONN_F_XXX.
 */
enum dpvs_fwd_mode {
	DPVS_FWD_MASQ           = IP_VS_CONN_F_MASQ,
	DPVS_FWD_LOCALNODE      = IP_VS_CONN_F_LOCALNODE,
	DPVS_FWD_MODE_TUNNEL    = IP_VS_CONN_F_TUNNEL,
	DPVS_FWD_MODE_DR        = IP_VS_CONN_F_DROUTE,
	DPVS_FWD_MODE_BYPASS    = IP_VS_CONN_F_BYPASS,
	DPVS_FWD_MODE_FNAT      = IP_VS_CONN_F_FULLNAT,
	DPVS_FWD_MODE_SNAT      = IP_VS_CONN_F_SNAT,
	DPVS_FWD_MODE_NAT       = DPVS_FWD_MASQ,
};

enum {
    DPVS_DEST_F_AVAILABLE   = 0x1<<0, // dest removed
    DPVS_DEST_F_OVERLOAD    = 0x1<<1, // too many conns
    DPVS_DEST_F_INHIBITED   = 0x1<<2, // dest forwarding failure
};

typedef struct dp_vs_dest_compat {
    /* destination server address */
    int                af;
    uint16_t           port;
    uint16_t           proto;
    uint32_t           weight;       /* destination weight */
    union inet_addr    addr;

    uint16_t           conn_flags;   /* flags passed on to connections */
    uint16_t           flags;        /* dest flags */

    enum dpvs_fwd_mode fwdmode;
    /* real server options */

    /* thresholds for active connections */
    uint32_t           max_conn;     /* upper threshold */
    uint32_t           min_conn;     /* lower threshold */

    uint32_t           actconns;     /* active connections */
    uint32_t           inactconns;   /* inactive connections */
    uint32_t           persistconns; /* persistent connections */

    /* statistics */
    struct dp_vs_stats stats;
} dpvs_dest_compat_t;

typedef struct dp_vs_dest_table {
    int             af;
    uint16_t        proto;
    uint16_t        port;
    uint32_t        fwmark;
    union inet_addr addr;

    unsigned int    num_dests;

    struct dp_vs_match match;

    lcoreid_t       cid;
    lcoreid_t       index;

    dpvs_dest_compat_t entrytable[0];
} dpvs_dest_table_t;

#define  dp_vs_get_dests  dp_vs_dest_table
#define  dp_vs_dest_entry dp_vs_dest_compat
#define  dp_vs_dest_conf  dp_vs_dest_compat

#ifdef CONFIG_DPVS_AGENT
typedef struct dp_vs_dest_front {
    uint32_t           af;
    uint16_t           proto;
    uint16_t           port;
    uint32_t           fwmark;
    union inet_addr    addr;
    unsigned int       num_dests;
    struct dp_vs_match match;
    uint32_t           cid;
    uint32_t           index;
} dpvs_dest_front_t;
#define  dp_vs_dest_detail dp_vs_dest_compat
#endif

#endif /* __DPVS_DEST_CONF_H__ */
