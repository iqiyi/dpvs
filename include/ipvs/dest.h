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
#ifndef __DPVS_DEST_H__
#define __DPVS_DEST_H__

#include "conf/dest.h"
#include "ipvs/service.h"

#include "conf/common.h"
#include "list.h"
#include "dpdk.h"
#include "timer.h"

union dest_check {
    struct {
        uint16_t origin_weight;
        uint16_t down_notice_recvd; // how many DOWN notifications has received
        uint32_t inhibit_duration;  // inhibited duration on failure, gains/loses exponentially, in seconds
        struct dpvs_timer timer;    // down-wait-timer in UP state, rs-inhibit-timer in DOWN state
    } master;
    struct {
        uint16_t origin_weight;
        uint16_t warm_up_count;     // how many UP notifications has sent after state going Up
    } slave;
};

struct dp_vs_dest {
    struct list_head    n_list;     /* for the dests in the service */

    int                 af;         /* address family */
    /*
     * normally, addr/port is for Real Server,
     * but for SNAT, addr/port is the "to-source"
     * (the target source ip/port translated to).
     */
    union inet_addr     addr;       /* IP address of the server */
    uint16_t            port;       /* port number of the server */

    volatile uint16_t   flags;      /* dest status flags */
    rte_atomic16_t      conn_flags; /* flags to copy to conn */
    rte_atomic16_t      weight;     /* server weight */

    rte_atomic32_t      refcnt;     /* reference counter */
    struct dp_vs_stats  stats;      /* Use per-cpu statistics for destination server */

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
    unsigned            limit_proportion; /* limit copied from svc*/

    union dest_check    dfc;        /* failure detection and inhibition */
} __rte_cache_aligned;

static inline bool
dp_vs_dest_is_avail(const struct dp_vs_dest *dest)
{
    return (dest->flags & DPVS_DEST_F_AVAILABLE) ? true : false;
}

static inline void
dp_vs_dest_set_avail(struct dp_vs_dest *dest)
{
    dest->flags |= DPVS_DEST_F_AVAILABLE;
}

static inline void
dp_vs_dest_clear_avail(struct dp_vs_dest *dest)
{
    dest->flags &= ~DPVS_DEST_F_AVAILABLE;
}

static inline bool
dp_vs_dest_is_overload(const struct dp_vs_dest *dest)
{
    return (dest->flags & DPVS_DEST_F_OVERLOAD) ? true : false;
}

static inline bool
dp_vs_dest_is_inhibited(const struct dp_vs_dest *dest)
{
    return (dest->flags & DPVS_DEST_F_INHIBITED) ? true : false;
}

static inline void
dp_vs_dest_set_inhibited(struct dp_vs_dest *dest)
{
    dest->flags |= DPVS_DEST_F_INHIBITED;
}

static inline void
dp_vs_dest_clear_inhibited(struct dp_vs_dest *dest)
{
    dest->flags &= ~DPVS_DEST_F_INHIBITED;
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
            && !dp_vs_dest_is_inhibited(dest)
            && dp_vs_dest_get_weight(dest) > 0) ? true : false;
}

int dp_vs_dest_new(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest,
                                              struct dp_vs_dest **dest_p);

struct dp_vs_dest *dp_vs_dest_lookup(int af, struct dp_vs_service *svc,
                                     const union inet_addr *daddr, uint16_t dport);

int dp_vs_dest_add(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest);

int dp_vs_dest_edit(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest);

int dp_vs_dest_edit_health(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest);

void dp_vs_dest_unlink(struct dp_vs_service *svc,
                        struct dp_vs_dest *dest, int svcupd);

void dp_vs_dest_put(struct dp_vs_dest *dest, bool timerlock);

int dp_vs_dest_del(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest);

int dp_vs_dest_get_entries(const struct dp_vs_service *svc,
                           struct dp_vs_get_dests *uptr);

int dp_vs_dest_detected_alive(struct dp_vs_dest *dest);
int dp_vs_dest_detected_dead(struct dp_vs_dest *dest);

int dp_vs_dest_init(void);

int dp_vs_dest_term(void);

#endif /* __DPVS_DEST_H__ */
