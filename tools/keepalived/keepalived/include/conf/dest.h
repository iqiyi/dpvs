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
#ifndef __DPVS_DEST_CONF_H__
#define __DPVS_DEST_CONF_H__

#include "conf/service.h"

/* must consistent with IP_VS_CONN_F_XXX (libipvs-2.6/ip_vs.h) */
enum dpvs_fwd_mode {
    DPVS_FWD_MASQ           = 0,
    DPVS_FWD_LOCALNODE      = 1,
    DPVS_FWD_MODE_TUNNEL    = 2,
    DPVS_FWD_MODE_DR        = 3,
    DPVS_FWD_MODE_BYPASS    = 4,
    DPVS_FWD_MODE_FNAT      = 5,
    DPVS_FWD_MODE_NAT       = DPVS_FWD_MASQ,
    DPVS_FWD_MODE_SNAT      = 6,
};

enum {
    DPVS_DEST_F_AVAILABLE       = 0x1<<0,
    DPVS_DEST_F_OVERLOAD        = 0x1<<1,
};

struct dp_vs_dest_conf {
    /* destination server address */
    int                af;
    union inet_addr    addr;
    uint16_t           port;

    enum dpvs_fwd_mode fwdmode;
    /* real server options */
    unsigned           conn_flags;    /* connection flags */
    int                weight;     /* destination weight */

    /* thresholds for active connections */
    uint32_t           max_conn;    /* upper threshold */
    uint32_t           min_conn;    /* lower threshold */
};

struct dp_vs_dest_entry {
    int             af;
    union inet_addr addr;        /* destination address */
    uint16_t        port;
    unsigned        conn_flags;    /* connection flags */
    int             weight;     /* destination weight */

    uint32_t        max_conn;  /* upper threshold */
    uint32_t        min_conn;  /* lower threshold */

    uint32_t        actconns;  /* active connections */
    uint32_t        inactconns;   /* inactive connections */
    uint32_t        persistconns; /* persistent connections */

    /* statistics */
    struct dp_vs_stats stats;
};

struct dp_vs_get_dests {
    /* which service: user fills in these */
    int              af;
    uint16_t         proto;
    union inet_addr  addr;        /* virtual address */
    uint16_t         port;
    uint32_t         fwmark;       /* firwall mark of service */

    /* number of real servers */
    unsigned int num_dests;

    lcoreid_t        cid;

    char        srange[256];
    char        drange[256];
    char        iifname[IFNAMSIZ];
    char        oifname[IFNAMSIZ];

    /* the real servers */
    struct dp_vs_dest_entry entrytable[0];
};

struct dp_vs_dest_user {
    int             af;
    union inet_addr addr;
    uint16_t        port;

    unsigned        conn_flags;
    int             weight;

    uint32_t        max_conn;
    uint32_t        min_conn;
};

#endif /* __DPVS_DEST_CONF_H__ */
