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
#ifndef __DPVS_DEST_H__
#define __DPVS_DEST_H__

#include "ipvs/service.h"

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

#ifdef __DPVS__
#include "common.h"
#include "list.h"
#include "dpdk.h"

struct dp_vs_dest {
    struct list_head    n_list;     /* for the dests in the service */
    struct list_head    d_list;     /* for table with all the dests */

    int                 af;         /* address family */
    /*
     * normally, addr/port is for Real Server,
     * but for SNAT, addr/port is the "to-source"
     * (the target source ip/port translated to).
     */
    union inet_addr     addr;       /* IP address of the server */
    uint16_t            port;       /* port number of the server */

    volatile unsigned   flags;      /* dest status flags */
    rte_atomic16_t      conn_flags; /* flags to copy to conn */
    rte_atomic16_t      weight;     /* server weight */

    rte_atomic32_t      refcnt;     /* reference counter */
    struct dp_vs_stats  *stats;     /* Use per-cpu statistics for destination server */

    enum dpvs_fwd_mode  fwdmode;

    /* connection counters and thresholds */
    rte_atomic32_t      actconns;   /* active connections */
    rte_atomic32_t      inactconns; /* inactive connections */
    rte_atomic32_t      persistconns;   /* persistent connections */
    uint32_t            max_conn;   /* upper threshold */
    uint32_t            min_conn;   /* lower threshold */

    /* for virtual service */
    uint16_t            proto;      /* which protocol (TCP/UDP) */
    uint16_t            vport;      /* virtual port number */
    uint32_t            vfwmark;    /* firewall mark of service */
    struct dp_vs_service *svc;      /* service it belongs to */
    union inet_addr     vaddr;      /* virtual IP address */
    unsigned            conn_timeout; /* conn timeout copied from svc*/
    unsigned            limit_proportion; /* limit copied from svc*/
} __rte_cache_aligned;
#endif

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

    char        srange[256];
    char        drange[256];
    char        iifname[IFNAMSIZ];
    char        oifname[IFNAMSIZ];

    /* the real servers */
    struct dp_vs_dest_entry entrytable[0];
};

struct dp_vs_dest_user{
    int             af;
    union inet_addr addr;
    uint16_t        port;

    unsigned        conn_flags;
    int             weight;

    uint32_t        max_conn;
    uint32_t        min_conn;
};

#ifdef __DPVS__
static inline bool
dp_vs_dest_is_avail(struct dp_vs_dest *dest)
{
    return (dest->flags & DPVS_DEST_F_AVAILABLE) ? true : false;
}

static inline bool
dp_vs_dest_is_overload(struct dp_vs_dest *dest)
{
    return (dest->flags & DPVS_DEST_F_OVERLOAD) ? true : false;
}

static inline int16_t
dp_vs_dest_get_weight(struct dp_vs_dest *dest)
{
    return rte_atomic16_read(&dest->weight);
}

static inline bool
dp_vs_dest_is_valid(struct dp_vs_dest *dest)
{
    return (dest
            && dp_vs_dest_is_avail(dest)
            && !dp_vs_dest_is_overload(dest)
            && dp_vs_dest_get_weight(dest) > 0) ? true : false;
}

int dp_vs_new_dest(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest,
                                              struct dp_vs_dest **dest_p);

struct dp_vs_dest *dp_vs_lookup_dest(int af, struct dp_vs_service *svc,
                                     const union inet_addr *daddr, uint16_t dport);

struct dp_vs_dest *dp_vs_trash_get_dest(struct dp_vs_service *svc,
                                        const union inet_addr *daddr, uint16_t dport);

void dp_vs_trash_cleanup(void);

int dp_vs_add_dest(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest);

int dp_vs_edit_dest(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest);

void __dp_vs_unlink_dest(struct dp_vs_service *svc,
                        struct dp_vs_dest *dest, int svcupd);

void __dp_vs_del_dest(struct dp_vs_dest *dest);

int dp_vs_del_dest(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest);

int dp_vs_get_dest_entries(const struct dp_vs_service *svc,
                           const struct dp_vs_get_dests *get,
                           struct dp_vs_get_dests *uptr);

int dp_vs_dest_init(void);

int dp_vs_dest_term(void);
#endif

#endif /* __DPVS_DEST_H__ */
