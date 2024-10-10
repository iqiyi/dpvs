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
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>
#include "dpdk.h"
#include "list.h"
#include "conf/common.h"
#include "netif.h"
#include "route.h"
#include "inet.h"
#include "ctrl.h"
#include "sa_pool.h"
#include "ipvs/ipvs.h"
#include "ipvs/service.h"
#include "ipvs/conn.h"
#include "ipvs/dest.h"
#include "ipvs/laddr.h"
#include "conf/laddr.h"

/*
 * Local Address (LIP) and port (lport) allocation for FNAT mode,
 *
 * 1. Four tuple of IP connection <sip:sport, dip:dport> must be unique.
 *    we cannot control RS's <rip:rport> while we really need support
 *    millions of connections. so one laddr is not enough (only lport
 *    is variable means 2^16 is the max connection number).
 *
 *    So we need more laddr and an algorithm to select it, so as lport.
 *
 * 2. laddr maintained by service.
 *
 * Note: FDIR and <lip:lport> selection is handled by sa_pool module now.
 *
 * 3. select <lip:lport> for FDIR
 *
 *    consider conn table is per-lcore, we must
 *    make sure outbound flow handled by same lcore.
 *    so we use FDIR to set oubound flow to same lcore as inbound.
 *    note FDIR has limited filter number (8K),
 *    both <lip:lport> 2^32*2^16 and <lport> 2^16 are too big.
 *
 *    actually we just need N fdir filter, while N >= #lcore
 *    so we use LSB B bits of lport for fdir mask, let
 *    2^B >= (N == #lcore)
 *
 *    further more, for the case inbound/outbound port are same,
 *    vport will fdir by mistake, then RSS will not work for inbound.
 *
 *    thus we we need fdir LIP as well, the total number of filters
 *    we needed is: "#lcore * #lip".
 *
 * 4. why use LSB bits instead of MSB for FDIR mask ?
 *
 *    MSB was used, it makes lport range continuous and more clear
 *    for each lcores, for example
 *
 *      lcore   lport-range
 *      0       0~4095
 *      1       4096~8191
 *
 *    But consider global min/max limitations, like we should
 *    skip port 0~1024 or 50000~65535. it causes lport resource
 *    of some lcore exhausted prematurely. That's not acceptable.
 *
 *    Using LSB bits solves this issue, although the lports for
 *    each lcore is distributed.
 *
 * 5. Just an option: use laddr instead of lport to mapping lcore.
 *    __BUT__ laddr is an per-service configure from user's point.
 *
 *    a) use one laddr or more for each lcore.
 *    b) select laddr according to lcore
 *    c) set laddr to FDIR.
 *
 *    to use lport-mask we can save laddr, but it's not easy set
 *    fdir for TCP/UDP related ICMP (or too complex).
 *    and using laddr-lcore 1:1 mapping, it consumes more laddr,
 *    but note one laddr supports at about 6W conn (same rip:rport).
 *    It man not make sence to let #lcore bigger then #laddr.
 */

struct dp_vs_laddr {
    int                     af;
    struct list_head        list;       /* svc->laddr_list elem */
    union inet_addr         addr;
    rte_atomic32_t          refcnt;
    rte_atomic32_t          conn_counts;

    struct netif_port       *iface;
};

static uint32_t dp_vs_laddr_max_trails = 16;

static inline int __laddr_step(struct dp_vs_service *svc)
{
   /* Why can't we always use the next laddr(rr scheduler) to setup new session?
    * Because realserver rr/wrr scheduler may get synchronous with the laddr rr
    * scheduler. If so, the local IP may stay invariant for a specified realserver,
    * which is a hurt for realserver concurrency performance. To avoid the problem,
    * we just choose 5% sessions to use the one after the next laddr randomly.
    * */
    if (strncmp(svc->scheduler->name, "rr", 2) == 0 ||
            strncmp(svc->scheduler->name, "wrr", 3) == 0)
        return rte_rand_max(100) < 5 ? 2 : 1;

    return 1;
}

static inline struct dp_vs_laddr *__get_laddr(struct dp_vs_service *svc)
{
    int step;
    struct dp_vs_laddr *laddr = NULL;

    /* if list not inited ? list_empty() returns true ! */
    assert(svc->laddr_list.next);

    if (list_empty(&svc->laddr_list)) {
        return NULL;
    }

    step = __laddr_step(svc);
    while (step-- > 0) {
        if (unlikely(!svc->laddr_curr))
            svc->laddr_curr = svc->laddr_list.next;
        else
            svc->laddr_curr = svc->laddr_curr->next;

        if (svc->laddr_curr == &svc->laddr_list)
            svc->laddr_curr = svc->laddr_list.next;
    }

    laddr = list_entry(svc->laddr_curr, struct dp_vs_laddr, list);
    rte_atomic32_inc(&laddr->refcnt);

    return laddr;
}

static inline void put_laddr(struct dp_vs_laddr *laddr)
{
    if (!laddr)
        return;

    if (rte_atomic32_dec_and_test(&laddr->refcnt)) {
        rte_free(laddr);
#ifdef CONFIG_DPVS_IPVS_DEBUG
        RTE_LOG(DEBUG, IPVS, "%s: [%02d] delete laddr.\n", __func__, rte_lcore_id());
#endif
    }
}

int dp_vs_laddr_bind(struct dp_vs_conn *conn, struct dp_vs_service *svc)
{
    struct dp_vs_laddr *laddr = NULL;
    int i;
    uint16_t sport = 0;
    struct sockaddr_storage dsin, ssin;
    bool found = false;

    if (!conn || !conn->dest || !svc)
        return EDPVS_INVAL;
    if (svc->proto != IPPROTO_TCP && svc->proto != IPPROTO_UDP && 
		svc->proto != IPPROTO_SCTP)
        return EDPVS_NOTSUPP;
    if (dp_vs_conn_is_template(conn))
        return EDPVS_OK;

    /*
     * some time allocate lport fails for one laddr,
     * but there's also some resource on another laddr.
     */
    for (i = 0; i < dp_vs_laddr_max_trails && i < svc->num_laddrs; i++) {
        /* select a local IP from service */
        laddr = __get_laddr(svc);
        if (!laddr) {
            RTE_LOG(ERR, IPVS, "%s: no laddr available.\n", __func__);
            return EDPVS_RESOURCE;
        }

        memset(&dsin, 0, sizeof(struct sockaddr_storage));
        memset(&ssin, 0, sizeof(struct sockaddr_storage));

        if (laddr->af == AF_INET) {
            struct sockaddr_in *daddr, *saddr;
            daddr = (struct sockaddr_in *)&dsin;
            daddr->sin_family = laddr->af;
            daddr->sin_addr = conn->daddr.in;
            daddr->sin_port = conn->dport;
            saddr = (struct sockaddr_in *)&ssin;
            saddr->sin_family = laddr->af;
            saddr->sin_addr = laddr->addr.in;
        } else {
            struct sockaddr_in6 *daddr, *saddr;
            daddr = (struct sockaddr_in6 *)&dsin;
            daddr->sin6_family = laddr->af;
            daddr->sin6_addr = conn->daddr.in6;
            daddr->sin6_port = conn->dport;
            saddr = (struct sockaddr_in6 *)&ssin;
            saddr->sin6_family = laddr->af;
            saddr->sin6_addr = laddr->addr.in6;
        }

        if (sa_fetch(laddr->af, laddr->iface, &dsin, &ssin) != EDPVS_OK) {
            char buf[64];
            if (inet_ntop(laddr->af, &laddr->addr, buf, sizeof(buf)) == NULL)
                snprintf(buf, sizeof(buf), "::");

#ifdef CONFIG_DPVS_IPVS_DEBUG
            RTE_LOG(DEBUG, IPVS, "%s: [%02d] no lport available on %s, "
                    "try next laddr.\n", __func__, rte_lcore_id(), buf);
#endif
            put_laddr(laddr);
            continue;
        }

        sport = (laddr->af == AF_INET ? (((struct sockaddr_in *)&ssin)->sin_port)
                : (((struct sockaddr_in6 *)&ssin)->sin6_port));
        found = true;
        break;
    }

    if (!found) {
#ifdef CONFIG_DPVS_IPVS_DEBUG
        RTE_LOG(ERR, IPVS, "%s: [%02d] no lip/lport available !!\n",
                __func__, rte_lcore_id());
#endif
        return EDPVS_RESOURCE;
    }

    rte_atomic32_inc(&laddr->conn_counts);

    /* overwrite related fields in out-tuplehash and conn */
    conn->laddr = laddr->addr;
    conn->lport = sport;
    tuplehash_out(conn).daddr = laddr->addr;
    tuplehash_out(conn).dport = sport;

    conn->local = laddr;
    return EDPVS_OK;
}

int dp_vs_laddr_unbind(struct dp_vs_conn *conn)
{
    struct sockaddr_storage dsin, ssin;

    if (dp_vs_conn_is_template(conn))
        return EDPVS_OK;

    if (!conn->local)
        return EDPVS_OK; /* not FNAT ? */

    memset(&dsin, 0, sizeof(struct sockaddr_storage));
    memset(&ssin, 0, sizeof(struct sockaddr_storage));

    if (conn->local->af == AF_INET) {
        struct sockaddr_in *daddr, *saddr;
        daddr = (struct sockaddr_in *)&dsin;
        daddr->sin_family = conn->local->af;
        daddr->sin_addr = conn->daddr.in;
        daddr->sin_port = conn->dport;
        saddr = (struct sockaddr_in *)&ssin;
        saddr->sin_family = conn->local->af;
        saddr->sin_addr = conn->laddr.in;
        saddr->sin_port = conn->lport;
    } else {
        struct sockaddr_in6 *daddr, *saddr;
        daddr = (struct sockaddr_in6 *)&dsin;
        daddr->sin6_family = conn->local->af;
        daddr->sin6_addr = conn->daddr.in6;
        daddr->sin6_port = conn->dport;
        saddr = (struct sockaddr_in6 *)&ssin;
        saddr->sin6_family = conn->local->af;
        saddr->sin6_addr = conn->laddr.in6;
        saddr->sin6_port = conn->lport;
    }

    sa_release(conn->local->iface, &dsin, &ssin);

    rte_atomic32_dec(&conn->local->conn_counts);

    put_laddr(conn->local);
    conn->local = NULL;
    return EDPVS_OK;
}

int dp_vs_laddr_add(struct dp_vs_service *svc,
                    int af, const union inet_addr *addr,
                    const char *ifname)
{
    struct dp_vs_laddr *new, *curr;

    if (!svc || !addr)
        return EDPVS_INVAL;

    new = rte_malloc(NULL, sizeof(*new),
                            RTE_CACHE_LINE_SIZE);
    if (!new)
        return EDPVS_NOMEM;

    new->af = af;
    new->addr = *addr;
    rte_atomic32_set(&new->refcnt, 1);
    rte_atomic32_init(&new->conn_counts);

    /* is the laddr bind to local interface ? */
    new->iface = netif_port_get_by_name(ifname);
    if (unlikely(!new->iface)) {
        rte_free(new);
        return EDPVS_NOTEXIST;
    }

    list_for_each_entry(curr, &svc->laddr_list, list) {
        if (af == curr->af && inet_addr_equal(af, &curr->addr, &new->addr)) {
            rte_free(new);
            return EDPVS_EXIST;
        }
    }

    list_add_tail(&new->list, &svc->laddr_list);
    svc->num_laddrs++;

    return EDPVS_OK;
}

int dp_vs_laddr_del(struct dp_vs_service *svc, int af, const union inet_addr *addr)
{
    struct dp_vs_laddr *laddr, *next;
    int err = EDPVS_NOTEXIST;

    if (!svc || !addr)
        return EDPVS_INVAL;

    list_for_each_entry_safe(laddr, next, &svc->laddr_list, list) {
        if (!((af == laddr->af) && inet_addr_equal(af, &laddr->addr, addr)))
            continue;

        /* found */
        if (svc->laddr_curr == &laddr->list)
                svc->laddr_curr = laddr->list.next;
        list_del(&laddr->list);
        svc->num_laddrs--;
        put_laddr(laddr);
        err = EDPVS_OK;
    }

    return err;
}

#ifdef CONFIG_DPVS_AGENT
static int dpvs_agent_laddr_getall(struct dp_vs_service *svc,
                              struct dp_vs_laddr_detail **addrs, size_t *naddr)
{
    struct dp_vs_laddr *laddr;
    int i;

    if (!svc || !addrs || !naddr)
        return EDPVS_INVAL;

    if (svc->num_laddrs > 0) {
        *naddr = svc->num_laddrs;
        *addrs = rte_malloc(0, sizeof(struct dp_vs_laddr_detail) * svc->num_laddrs,
                RTE_CACHE_LINE_SIZE);
        if (!(*addrs)) {
            return EDPVS_NOMEM;
        }

        i = 0;
        list_for_each_entry(laddr, &svc->laddr_list, list) {
            assert(i < *naddr);
            (*addrs)[i].af = laddr->af;
            (*addrs)[i].addr = laddr->addr;
            (*addrs)[i].conns = rte_atomic32_read(&laddr->conn_counts);
            rte_strlcpy((*addrs)[i].ifname, laddr->iface->name, IFNAMSIZ);
            i++;
        }
    } else {
        *naddr = 0;
        *addrs = NULL;
    }

    return EDPVS_OK;
}
#endif /* CONFIG_DPVS_AGENT */

/* if success, it depend on caller to free @addrs by rte_free() */
static int dp_vs_laddr_getall(struct dp_vs_service *svc,
                              struct dp_vs_laddr_entry **addrs, size_t *naddr)
{
    struct dp_vs_laddr *laddr;
    int i;

    if (!svc || !addrs || !naddr)
        return EDPVS_INVAL;

    if (svc->num_laddrs > 0) {
        *naddr = svc->num_laddrs;
        *addrs = rte_malloc(0, sizeof(struct dp_vs_laddr_entry) * svc->num_laddrs,
                RTE_CACHE_LINE_SIZE);
        if (!(*addrs)) {
            return EDPVS_NOMEM;
        }

        i = 0;
        list_for_each_entry(laddr, &svc->laddr_list, list) {
            assert(i < *naddr);
            (*addrs)[i].af = laddr->af;
            (*addrs)[i].addr = laddr->addr;
            (*addrs)[i].nconns = rte_atomic32_read(&laddr->conn_counts);
            i++;
        }
    } else {
        *naddr = 0;
        *addrs = NULL;
    }

    return EDPVS_OK;
}

int dp_vs_laddr_flush(struct dp_vs_service *svc)
{
    struct dp_vs_laddr *laddr, *next;
    int err = EDPVS_OK;

    if (!svc)
        return EDPVS_INVAL;

    list_for_each_entry_safe(laddr, next, &svc->laddr_list, list) {
        if (svc->laddr_curr == &laddr->list)
                svc->laddr_curr = laddr->list.next;
        list_del(&laddr->list);
        svc->num_laddrs--;
        put_laddr(laddr);
        err = EDPVS_OK;
    }

    return err;
}

/*
 * for control plane
 */

static uint32_t laddr_msg_seq(void)
{
    static uint32_t counter = 0;
    return counter++;
}

static inline sockoptid_t set_opt_so2msg(int opt)
{
    // return opt - SOCKOPT_LADDR_BASE + MSG_TYPE_SET_LADDR_BASE;
    switch (opt) {
    case SOCKOPT_SET_LADDR_ADD:
        return MSG_TYPE_LADDR_SET_ADD;
    case SOCKOPT_SET_LADDR_DEL:
        return MSG_TYPE_LADDR_SET_DEL;
    case SOCKOPT_SET_LADDR_FLUSH:
        return MSG_TYPE_LADDR_SET_FLUSH;
    case SOCKOPT_GET_LADDR_GETALL:
        return MSG_TYPE_LADDR_GET_ALL;
#ifdef CONFIG_DPVS_AGENT
    case DPVSAGENT_VS_ADD_LADDR:
        return MSG_TYPE_AGENT_ADD_LADDR;
    case DPVSAGENT_VS_DEL_LADDR:
        return MSG_TYPE_AGENT_DEL_LADDR;
    case DPVSAGENT_VS_GET_LADDR:
        return MSG_TYPE_AGENT_GET_LADDR;
#endif
    default:
        return -1;
    }
}

static int laddr_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct dp_vs_laddr_conf *laddr_conf = conf;
    struct dp_vs_service *svc;
    int err, af;
    uint16_t proto, port;
    uint32_t fwmark;
    const struct dp_vs_match *match;
    const union inet_addr *addr;
#ifdef CONFIG_DPVS_AGENT
    uint32_t i;
    const struct dp_vs_laddr_front *laddr_front = conf;
    struct dp_vs_laddr_detail *details, *detail;
#endif

    err = EDPVS_OK;
    lcoreid_t cid = rte_lcore_id();

    // send to slave core
    if (cid == rte_get_main_lcore()) {
        struct dpvs_msg *msg;

        msg = msg_make(set_opt_so2msg(opt), laddr_msg_seq(), DPVS_MSG_MULTICAST, cid, size, conf);
        if (!msg)
            return EDPVS_NOMEM;

        err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
        /* go on in master core, not return */
        if (err != EDPVS_OK)
            RTE_LOG(ERR, SERVICE, "[%s] fail to send multicast message\n", __func__);
        msg_destroy(&msg);
    }

    if (!conf && size < sizeof(*laddr_conf))
        return EDPVS_INVAL;

#ifdef CONFIG_DPVS_AGENT
    if (opt == DPVSAGENT_VS_ADD_LADDR || opt == DPVSAGENT_VS_DEL_LADDR) {
        af     = (int)laddr_front->af;
        proto  = (uint16_t)laddr_front->proto;
        port   = (uint16_t)laddr_front->port;
        fwmark = (uint32_t)laddr_front->fwmark;
        addr   = &laddr_front->addr;
        match  = &laddr_front->match;
    } else {
#endif
        af     = (int)laddr_conf->af_s;
        proto  = (uint16_t)laddr_conf->proto;
        port   = (uint16_t)laddr_conf->vport;
        fwmark = (uint32_t)laddr_conf->fwmark;
        addr   = &laddr_conf->vaddr;
        match  = &laddr_conf->match;
#ifdef CONFIG_DPVS_AGENT
    }
#endif

    svc = dp_vs_service_lookup(af, proto, addr, port,
            fwmark, NULL, match, rte_lcore_id());
    if (!svc)
        return EDPVS_NOSERV;

    switch (opt) {
    case SOCKOPT_SET_LADDR_ADD:
        err = dp_vs_laddr_add(svc, laddr_conf->af_l, &laddr_conf->laddr,
                laddr_conf->ifname);
        break;
    case SOCKOPT_SET_LADDR_DEL:
        err = dp_vs_laddr_del(svc, laddr_conf->af_l, &laddr_conf->laddr);
        break;
    case SOCKOPT_SET_LADDR_FLUSH:
        err = dp_vs_laddr_flush(svc);
        break;
#ifdef CONFIG_DPVS_AGENT
    case DPVSAGENT_VS_ADD_LADDR:
        details = (struct dp_vs_laddr_detail*)((char*)conf + sizeof(struct dp_vs_laddr_front));
        for (i = 0; i < laddr_front->count; i++) {
            detail = (struct dp_vs_laddr_detail*)((char*)details + sizeof(struct dp_vs_laddr_detail) * i);
            err = dp_vs_laddr_add(svc, detail->af, &detail->addr, detail->ifname);
            if (err != EDPVS_OK) {
                if (err == EDPVS_EXIST)
                    continue;
                break;
            }
        }
        break;
    case DPVSAGENT_VS_DEL_LADDR:
        details = (struct dp_vs_laddr_detail*)((char*)conf + sizeof(struct dp_vs_laddr_front));
        for (i = 0; i < laddr_front->count; i++) {
            detail = (struct dp_vs_laddr_detail*)((char*)details + sizeof(struct dp_vs_laddr_detail) * i);
            err = dp_vs_laddr_del(svc, detail->af, &detail->addr); 
            if (err != EDPVS_OK) {
                if (err == EDPVS_NOTEXIST)
                    continue;
                break;
            }
        }
        break;
#endif
    default:
        err = EDPVS_NOTSUPP;
        break;
    }

    return err;
}


#ifdef CONFIG_DPVS_AGENT
static int agent_get_msg_cb(struct dpvs_msg *msg)
{
    lcoreid_t cid = rte_lcore_id();
    struct dp_vs_laddr_front *laddr_conf, *laddrs;
    struct dp_vs_laddr_detail *addrs;
    struct dp_vs_service *svc;
    size_t naddr;
    int err, size, i;

    laddr_conf = (struct dp_vs_laddr_front *)msg->data;
    
    svc = dp_vs_service_lookup(laddr_conf->af, laddr_conf->proto,
                               &laddr_conf->addr, laddr_conf->port,
                               laddr_conf->fwmark, NULL, &laddr_conf->match, cid);
    if (!svc) {
        return EDPVS_NOSERV;
    } 

    err = dpvs_agent_laddr_getall(svc, &addrs, &naddr); 
    if (err != EDPVS_OK)
        return err;

    size = sizeof(*laddr_conf) + naddr * sizeof(struct dp_vs_laddr_detail);
    laddrs = msg_reply_alloc(size);
    if (!laddrs) {
        if (addrs)
            rte_free(addrs);
        return EDPVS_NOMEM;
    }

    *laddrs = *laddr_conf;
    laddrs->count = naddr;
    laddrs->cid = cid;
    // laddrs->index = g_lcore_id2index[cid];

    for (i = 0; i < naddr; i++) {
        laddrs->laddrs[i].af = addrs[i].af;
        laddrs->laddrs[i].addr = addrs[i].addr;
        /* TODO: nport_conflict & nconns */
        rte_memcpy(laddrs->laddrs[i].ifname, addrs[i].ifname, IFNAMSIZ);
        laddrs->laddrs[i].nport_conflict = 0;
        laddrs->laddrs[i].conns = addrs[i].conns;
    }
    if (addrs)
        rte_free(addrs);

    msg->reply.len = size;
    msg->reply.data = (void *)laddrs;
    return EDPVS_OK;
}
#endif

static int get_msg_cb(struct dpvs_msg *msg)
{
    lcoreid_t cid = rte_lcore_id();
    struct dp_vs_laddr_conf *laddr_conf, *laddrs;
    struct dp_vs_laddr_entry *addrs;
    struct dp_vs_service *svc;
    size_t naddr;
    int err, size, i;

    laddr_conf = (struct dp_vs_laddr_conf *)msg->data;

    svc = dp_vs_service_lookup(laddr_conf->af_s, laddr_conf->proto,
                               &laddr_conf->vaddr, laddr_conf->vport,
                               laddr_conf->fwmark, NULL, &laddr_conf->match, cid);
    if (!svc) {
        return EDPVS_NOSERV;
    } 
    err = dp_vs_laddr_getall(svc, &addrs, &naddr); 
    if (err != EDPVS_OK)
        return err;

    size = sizeof(*laddr_conf) + naddr * sizeof(struct dp_vs_laddr_entry);
    laddrs = msg_reply_alloc(size);
    if (!laddrs) {
        if (addrs)
            rte_free(addrs);
        return EDPVS_NOMEM;
    }

    *laddrs = *laddr_conf;
    laddrs->nladdrs = naddr;
    laddrs->cid = cid;
    laddrs->index = g_lcore_id2index[cid];
    for (i = 0; i < naddr; i++) {
        laddrs->laddrs[i].af = addrs[i].af;
        laddrs->laddrs[i].addr = addrs[i].addr;
        /* TODO: nport_conflict & nconns */
        laddrs->laddrs[i].nport_conflict = 0;
        laddrs->laddrs[i].nconns = addrs[i].nconns;
    }
    if (addrs)
        rte_free(addrs);

    msg->reply.len = size;
    msg->reply.data = (void *)laddrs;
    return EDPVS_OK;
}

static int dp_vs_copy_percore_laddrs_stats(struct dp_vs_laddr_conf *master_laddrs,
                                           struct dp_vs_laddr_conf *slave_laddrs)
{
    int i;
    if (master_laddrs->nladdrs != slave_laddrs->nladdrs)
        return EDPVS_INVAL;
    for (i = 0; i < master_laddrs->nladdrs; i++) {
        master_laddrs->laddrs[i].nport_conflict += slave_laddrs->laddrs[i].nport_conflict;
        master_laddrs->laddrs[i].nconns += slave_laddrs->laddrs[i].nconns;
    }

    return EDPVS_OK;
}

static int laddr_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    const struct dp_vs_laddr_conf *laddr_conf = conf;
    struct dp_vs_laddr_conf *laddrs, *get_msg;
#ifdef CONFIG_DPVS_AGENT
    const struct dp_vs_laddr_front *laddr_front;
    struct dp_vs_laddr_front *out_front, *iter_front;
    struct dp_vs_laddr_detail *details;
#endif
    struct dp_vs_service *svc;
    struct dp_vs_laddr_entry *addrs;
    size_t naddr, i;
    int err;
    struct dpvs_multicast_queue *reply = NULL;
    struct dpvs_msg *msg, *cur;
    lcoreid_t cid;

    switch (opt) {
        case SOCKOPT_GET_LADDR_GETALL:
            laddr_conf = conf;
            if (!conf || size < sizeof(*laddr_conf))
                return EDPVS_INVAL;

            cid = g_lcore_index2id[laddr_conf->index];
            if (cid < 0 || cid >= DPVS_MAX_LCORE)
                return EDPVS_INVAL;

            msg = msg_make(MSG_TYPE_LADDR_GET_ALL, 0, DPVS_MSG_MULTICAST, rte_lcore_id(),
                           sizeof(struct dp_vs_laddr_conf), laddr_conf);
            if (!msg)
                return EDPVS_NOMEM;

            err = multicast_msg_send(msg, 0, &reply);
            if (err != EDPVS_OK) {
                msg_destroy(&msg);
                RTE_LOG(ERR, SERVICE, "%s: send message fail.\n", __func__);
                return EDPVS_MSG_FAIL;
            }

            if (cid == rte_get_main_lcore()) {
                svc = dp_vs_service_lookup(laddr_conf->af_s, laddr_conf->proto,
                                           &laddr_conf->vaddr, laddr_conf->vport,
                                           laddr_conf->fwmark, NULL, &laddr_conf->match, cid);
                if (!svc) {
                    msg_destroy(&msg);
                    return EDPVS_NOSERV;
                }

                err = dp_vs_laddr_getall(svc, &addrs, &naddr);
                if (err != EDPVS_OK) {
                    msg_destroy(&msg);
                    return err;
                }
                
                *outsize = sizeof(*laddr_conf) + naddr * sizeof(struct dp_vs_laddr_entry);
                *out = rte_malloc(0, *outsize, RTE_CACHE_LINE_SIZE);
                if (!*out) {
                    if (addrs)
                        rte_free(addrs);
                    msg_destroy(&msg);
                    return EDPVS_NOMEM;
                }

                laddrs = *out;
                *laddrs = *laddr_conf;

                laddrs->nladdrs = naddr;
                laddrs->cid = cid;
                laddrs->index = g_lcore_id2index[cid];
                for (i = 0; i < naddr; i++) {
                    laddrs->laddrs[i].af = addrs[i].af;
                    laddrs->laddrs[i].addr = addrs[i].addr;
                    /* TODO: nport_conflict & nconns */
                    laddrs->laddrs[i].nport_conflict = 0;
                    laddrs->laddrs[i].nconns = addrs[i].nconns;
                }
                if (addrs)
                    rte_free(addrs);

                list_for_each_entry(cur, &reply->mq, mq_node) {
                    get_msg = (struct dp_vs_laddr_conf *)(cur->data);
                    err = dp_vs_copy_percore_laddrs_stats(laddrs, get_msg);
                    if (err != EDPVS_OK) {
                        msg_destroy(&msg);
                        rte_free(*out);
                        *out = NULL;
                        return err;
                    }
                }
                msg_destroy(&msg);
                return EDPVS_OK;

            } else {
                list_for_each_entry(cur, &reply->mq, mq_node) {
                    get_msg = (struct dp_vs_laddr_conf *)(cur->data);
                    if (cid == get_msg->cid) {
                        *outsize = sizeof(*laddr_conf) + \
                                   get_msg->nladdrs * sizeof(struct dp_vs_laddr_entry);
                        *out = rte_malloc(0, *outsize, RTE_CACHE_LINE_SIZE);
                        if (!*out) {
                            msg_destroy(&msg);
                            return EDPVS_NOMEM;
                        }
                        rte_memcpy(*out, get_msg, *outsize);
                        msg_destroy(&msg);
                        return EDPVS_OK;
                    }
                }
                RTE_LOG(ERR, SERVICE, "%s: find no laddr for cid=%d.\n", __func__, cid);
                msg_destroy(&msg);
                return EDPVS_NOTEXIST;
            }
#ifdef CONFIG_DPVS_AGENT
        case DPVSAGENT_VS_GET_LADDR:
            laddr_front = conf;
            if (!conf || size != sizeof(*laddr_front)) 
                return EDPVS_INVAL;

            msg = msg_make(MSG_TYPE_AGENT_GET_LADDR, 0, DPVS_MSG_MULTICAST, rte_lcore_id(), sizeof(struct dp_vs_laddr_front), laddr_front);
            if (!msg)
                return EDPVS_NOMEM;

            if (rte_lcore_id() != rte_get_main_lcore())
                return EDPVS_INVAL;

            err = multicast_msg_send(msg, 0, &reply);
            if (err != EDPVS_OK) {
                msg_destroy(&msg);
                RTE_LOG(ERR, SERVICE, "%s: send message fail.\n", __func__);
                return EDPVS_MSG_FAIL;
            }

            svc = dp_vs_service_lookup(laddr_front->af, laddr_front->proto,
                    &laddr_front->addr, laddr_front->port, laddr_front->fwmark,
                    NULL, &laddr_front->match, rte_get_main_lcore());
            if (!svc) {
                msg_destroy(&msg);
                return EDPVS_NOSERV;
            }

            err = dpvs_agent_laddr_getall(svc, &details, &naddr);
            if (err != EDPVS_OK) {
                msg_destroy(&msg);
                return err;
            }

            *outsize = sizeof(*laddr_front) + naddr * sizeof(struct dp_vs_laddr_detail);
            *out = rte_malloc(0, *outsize, RTE_CACHE_LINE_SIZE);
            if (!*out) {
                if (details)
                    rte_free(details);
                msg_destroy(&msg);
                return EDPVS_NOMEM;
            }
            
            out_front = *out;
            *out_front = *laddr_front;

            out_front->count = naddr;
            out_front->cid = rte_get_main_lcore();
            for (i = 0; i < naddr; i++) {
                out_front->laddrs[i].af = details[i].af;
                out_front->laddrs[i].addr = details[i].addr;
                rte_strlcpy(out_front->laddrs[i].ifname, details[i].ifname, IFNAMSIZ);
                out_front->laddrs[i].nport_conflict = 0;
                out_front->laddrs[i].conns = details[i].conns;
            }
            if (details)
                rte_free(details);
            list_for_each_entry(cur, &reply->mq, mq_node) {
                iter_front = (struct dp_vs_laddr_front*)(cur->data);
                if (iter_front->count != out_front->count) {
                    msg_destroy(&msg);
                    rte_free(*out);
                    *out = NULL;
                    RTE_LOG(ERR, SERVICE, "%s: The count(%d) of laddr in core(id = %d) not equal as main core laddr count(%d)\n", __func__, iter_front->count, iter_front->cid, out_front->count);
                    return EDPVS_INVAL;
                }
                for (i = 0; i < out_front->count; i++) {
                    out_front->laddrs[i].nport_conflict += iter_front->laddrs[i].nport_conflict;
                    out_front->laddrs[i].conns += iter_front->laddrs[i].conns;
                }
            }
            msg_destroy(&msg);
            return EDPVS_OK;
#endif /* CONFIG_DPVS_AGENT */
        default:
            return EDPVS_NOTSUPP;
    }
}

static struct dpvs_sockopts laddr_sockopts = {
    .version            = SOCKOPT_VERSION,
    .set_opt_min        = SOCKOPT_SET_LADDR_ADD,
    .set_opt_max        = SOCKOPT_SET_LADDR_FLUSH,
    .set                = laddr_sockopt_set,
    .get_opt_min        = SOCKOPT_GET_LADDR_GETALL,
    .get_opt_max        = SOCKOPT_GET_LADDR_MAX,
    .get                = laddr_sockopt_get,
};

#ifdef CONFIG_DPVS_AGENT
static struct dpvs_sockopts agent_laddr_sockopts = {
    .version            = SOCKOPT_VERSION,
    .set_opt_min        = DPVSAGENT_VS_ADD_LADDR,
    .set_opt_max        = DPVSAGENT_VS_DEL_LADDR,
    .set                = laddr_sockopt_set,
    .get_opt_min        = DPVSAGENT_VS_GET_LADDR,
    .get_opt_max        = DPVSAGENT_VS_GET_LADDR,
    .get                = laddr_sockopt_get,
};

static int agent_add_msg_cb(struct dpvs_msg *msg)
{
    return laddr_sockopt_set(DPVSAGENT_VS_ADD_LADDR, msg->data, msg->len);
}

static int agent_del_msg_cb(struct dpvs_msg *msg)
{
    return laddr_sockopt_set(DPVSAGENT_VS_DEL_LADDR, msg->data, msg->len);
}
#endif /* CONFIG_DPVS_AGENT */

static int add_msg_cb(struct dpvs_msg *msg)
{
    return laddr_sockopt_set(SOCKOPT_SET_LADDR_ADD, msg->data, msg->len);
}

static int del_msg_cb(struct dpvs_msg *msg)
{
    return laddr_sockopt_set(SOCKOPT_SET_LADDR_DEL, msg->data, msg->len);
}

static int flush_msg_cb(struct dpvs_msg *msg)
{
    return laddr_sockopt_set(SOCKOPT_SET_LADDR_FLUSH, msg->data, msg->len);
}

int dp_vs_laddr_init(void)
{
    int err;
    struct dpvs_msg_type msg_type;

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_LADDR_SET_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = add_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_LADDR_SET_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = del_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_LADDR_SET_FLUSH;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = flush_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }   

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_LADDR_GET_ALL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_LOW;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = get_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }

#ifdef CONFIG_DPVS_AGENT
    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_GET_LADDR;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_LOW;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = agent_get_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_ADD_LADDR;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = agent_add_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_DEL_LADDR;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = agent_del_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }
#endif

    if ((err = sockopt_register(&laddr_sockopts)) != EDPVS_OK)
        return err;

#ifdef CONFIG_DPVS_AGENT
    if ((err = sockopt_register(&agent_laddr_sockopts)) != EDPVS_OK)
        return err;
#endif

    return EDPVS_OK;
}

int dp_vs_laddr_term(void)
{
    int err;

#ifdef CONFIG_DPVS_AGENT
    if ((err = sockopt_unregister(&agent_laddr_sockopts)) != EDPVS_OK)
        return err;
#endif

    if ((err = sockopt_unregister(&laddr_sockopts)) != EDPVS_OK)
        return err;

    return EDPVS_OK;
}
