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
/*
 * svc will not be changed during svc get(svc is per core);
 * but conn will hold dest and dest will hold svc. so we need refcnt
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include "inet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "ipvs/blklst.h"
#include "ipvs/whtlst.h"
#include "ctrl.h"
#include "route.h"
#include "route6.h"
#include "netif.h"
#include "assert.h"
#include "neigh.h"
#include "ipset.h"

static rte_atomic16_t dp_vs_num_services[DPVS_MAX_LCORE];

/**
 * hash table for svc
 */
#define DP_VS_SVC_TAB_BITS 8
#define DP_VS_SVC_TAB_SIZE (1 << DP_VS_SVC_TAB_BITS)
#define DP_VS_SVC_TAB_MASK (DP_VS_SVC_TAB_SIZE - 1)

static struct list_head dp_vs_svc_table[DPVS_MAX_LCORE][DP_VS_SVC_TAB_SIZE];

static struct list_head dp_vs_svc_fwm_table[DPVS_MAX_LCORE][DP_VS_SVC_TAB_SIZE];

static struct list_head dp_vs_svc_match_list[DPVS_MAX_LCORE];

static inline int dp_vs_service_hashkey(int af, unsigned proto, const union inet_addr *addr)
{
    uint32_t addr_fold;

    addr_fold = inet_addr_fold(af, addr);

    if (!addr_fold) {
        RTE_LOG(DEBUG, SERVICE, "%s: IP proto not support.\n", __func__);
        return EDPVS_INVAL;
    }

    return (proto ^ rte_be_to_cpu_32(addr_fold)) & DP_VS_SVC_TAB_MASK;
}

static inline unsigned dp_vs_service_fwm_hashkey(uint32_t fwmark)
{
    return fwmark & DP_VS_SVC_TAB_MASK;
}

static int dp_vs_service_hash(struct dp_vs_service *svc, lcoreid_t cid)
{
    int hash;

    if (svc->flags & DP_VS_SVC_F_HASHED){
        RTE_LOG(DEBUG, SERVICE, "%s: request for already hashed.\n", __func__);
        return EDPVS_EXIST;
    }

    if (svc->fwmark) {
        hash = dp_vs_service_fwm_hashkey(svc->fwmark);
        list_add(&svc->f_list, &dp_vs_svc_fwm_table[cid][hash]);
    } else if (svc->match) {
        list_add(&svc->m_list, &dp_vs_svc_match_list[cid]);
    } else {
        /*
         *  Hash it by <protocol,addr,port> in dp_vs_svc_table
         */
        hash = dp_vs_service_hashkey(svc->af, svc->proto, &svc->addr);
        if (hash < 0)
             return EDPVS_INVAL;

        list_add(&svc->s_list, &dp_vs_svc_table[cid][hash]);
    }

    svc->flags |= DP_VS_SVC_F_HASHED;
    return EDPVS_OK;
}

static int dp_vs_service_unhash(struct dp_vs_service *svc)
{
    if (!(svc->flags & DP_VS_SVC_F_HASHED)) {
        RTE_LOG(DEBUG, SERVICE, "%s: request for unhashed flag.\n", __func__);
        return EDPVS_NOTEXIST;
    }

    if (svc->fwmark)
        list_del(&svc->f_list);
    else if (svc->match)
        list_del(&svc->m_list);
    else
        list_del(&svc->s_list);

    svc->flags &= ~DP_VS_SVC_F_HASHED;
    return EDPVS_OK;
}

static struct dp_vs_service *__dp_vs_service_get(int af, uint16_t protocol,
                                          const union inet_addr *vaddr,
                                          uint16_t vport, lcoreid_t cid)
{
    int hash;
    struct dp_vs_service *svc;

    hash = dp_vs_service_hashkey(af, protocol, vaddr);
    if (hash < 0)
        return NULL;
    list_for_each_entry(svc, &dp_vs_svc_table[cid][hash], s_list){
        if ((svc->af == af)
            && inet_addr_equal(af, &svc->addr, vaddr)
            && (svc->port == vport)
            && (svc->proto == protocol)) {
                return svc;
            }
    }

    return NULL;
}

static struct dp_vs_service *__dp_vs_service_fwm_get(int af, uint32_t fwmark, lcoreid_t cid)
{
    unsigned hash;
    struct dp_vs_service *svc;

    /* Check for fwmark addressed entries */
    hash = dp_vs_service_fwm_hashkey(fwmark);

    list_for_each_entry(svc, &dp_vs_svc_fwm_table[cid][hash], f_list) {
        if (svc->fwmark == fwmark && svc->af == af) {
            /* HIT */
            return svc;
        }
    }

    return NULL;
}

static inline bool __service_in_range(int af,
                                  const union inet_addr *addr, __be16 port,
                                  const struct inet_addr_range *range)
{
    if (unlikely((af == AF_INET) &&
        (ntohl(range->min_addr.in.s_addr) > ntohl(range->max_addr.in.s_addr))))
        return false;

    if (unlikely((af == AF_INET6) &&
        ipv6_addr_cmp(&range->min_addr.in6, &range->max_addr.in6) > 0))
        return false;

    if (unlikely(ntohs(range->min_port) > ntohs(range->max_port)))
        return false;

    /* if both min/max are zero, means need not check. */
    if (!inet_is_addr_any(af, &range->max_addr)) {
        if (af == AF_INET) {
            if (ntohl(addr->in.s_addr) < ntohl(range->min_addr.in.s_addr) ||
                ntohl(addr->in.s_addr) > ntohl(range->max_addr.in.s_addr))
                return false;
        } else {
            if (ipv6_addr_cmp(&range->min_addr.in6, &addr->in6) > 0 ||
                ipv6_addr_cmp(&range->max_addr.in6, &addr->in6) < 0)
                return false;
        }
    }

    if (range->max_port != 0) {
        if (ntohs(port) < ntohs(range->min_port) ||
            ntohs(port) > ntohs(range->max_port))
            return false;
    }

    return true;
}

static struct dp_vs_service *
__dp_vs_service_match_get4(const struct rte_mbuf *mbuf, bool *outwall, lcoreid_t cid)
{
    struct route_entry *rt = MBUF_USERDATA_CONST(mbuf, struct route_entry *, MBUF_FIELD_ROUTE);
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf); /* ipv4 only */
    struct dp_vs_service *svc;
    union inet_addr saddr, daddr;
    __be16 _ports[2], *ports;
    portid_t oif = NETIF_PORT_ID_ALL;

    saddr.in.s_addr = iph->src_addr;
    daddr.in.s_addr = iph->dst_addr;
    ports = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_ports), _ports);
    if (!ports)
        return NULL;

    /* snat is handled at pre-routing to check if oif
     * is match perform route here. */
    if (rt) {
        if ((rt->flag & RTF_KNI) || (rt->flag & RTF_LOCALIN))
            return NULL;
        oif = rt->port->id;
    } else if (outwall != NULL && (NULL != ipset_addr_lookup(AF_INET, &daddr))
                               && (rt = route_gfw_net_lookup(&daddr.in))) {
        char dst[64];
        RTE_LOG(DEBUG, IPSET, "%s: IP %s is in the gfwip set, found route in the outwall table.\n", __func__,
                              inet_ntop(AF_INET, &daddr, dst, sizeof(dst))? dst: "");
        oif = rt->port->id;
        route4_put(rt);
        *outwall = true;
    } else {
        rt = route4_input(mbuf, &daddr.in, &saddr.in,
                          iph->type_of_service,
                          netif_port_get(mbuf->port));
        if (!rt)
            return NULL;
        if ((rt->flag & RTF_KNI) || (rt->flag & RTF_LOCALIN)) {
            route4_put(rt);
            return NULL;
        }
        oif = rt->port->id;
        route4_put(rt);
    }

    list_for_each_entry(svc, &dp_vs_svc_match_list[cid], m_list) {
        struct dp_vs_match *m = svc->match;
        struct netif_port *idev, *odev;
        assert(m);

        if (!strlen(m->oifname))
            oif = NETIF_PORT_ID_ALL;

        idev = netif_port_get_by_name(m->iifname);
        odev = netif_port_get_by_name(m->oifname);

        if (svc->af == AF_INET && svc->proto == iph->next_proto_id &&
            __service_in_range(AF_INET, &saddr, ports[0], &m->srange) &&
            __service_in_range(AF_INET, &daddr, ports[1], &m->drange) &&
            (!idev || idev->id == mbuf->port) &&
            (!odev || odev->id == oif)
           ) {
            return svc;
        }
    }

    return NULL;
}

static struct dp_vs_service *
__dp_vs_service_match_get6(const struct rte_mbuf *mbuf, lcoreid_t cid)
{
    struct route6 *rt = MBUF_USERDATA_CONST(mbuf, struct route6 *, MBUF_FIELD_ROUTE);
    struct ip6_hdr *iph = ip6_hdr(mbuf);
    uint8_t ip6nxt = iph->ip6_nxt;
    struct dp_vs_service *svc;
    union inet_addr saddr, daddr;
    __be16 _ports[2], *ports;
    portid_t oif = NETIF_PORT_ID_ALL;

    struct flow6 fl6 = {
        .fl6_iif    = NULL,
        .fl6_daddr  = iph->ip6_dst,
        .fl6_saddr  = iph->ip6_src,
        .fl6_proto  = iph->ip6_nxt,
    };

    saddr.in6 = iph->ip6_src;
    daddr.in6 = iph->ip6_dst;
    ports = mbuf_header_pointer(mbuf, ip6_hdrlen(mbuf), sizeof(_ports), _ports);
    if (!ports)
        return NULL;

    /* snat is handled at pre-routing to check if oif
     * is match perform route here. */
    if (rt) {
        if ((rt->rt6_flags & RTF_KNI) || (rt->rt6_flags & RTF_LOCALIN))
            return NULL;
        oif = rt->rt6_dev->id;
    } else {
        rt = route6_input(mbuf, &fl6);
        if (!rt)
            return NULL;

        /* set mbuf userdata(MBUF_FIELD_ROUTE) to @rt as side-effect is not good!
         * although route will done again when out-xmit. */
        if ((rt->rt6_flags & RTF_KNI) || (rt->rt6_flags & RTF_LOCALIN)) {
            route6_put(rt);
            return NULL;
        }
        oif = rt->rt6_dev->id;
        route6_put(rt);
    }

    list_for_each_entry(svc, &dp_vs_svc_match_list[cid], m_list) {
        struct dp_vs_match *m = svc->match;
        struct netif_port *idev, *odev;
        assert(m);

        if (!strlen(m->oifname))
            oif = NETIF_PORT_ID_ALL;

        idev = netif_port_get_by_name(m->iifname);
        odev = netif_port_get_by_name(m->oifname);

        ip6_skip_exthdr(mbuf, sizeof(struct ip6_hdr), &ip6nxt);

        if (svc->af == AF_INET6 && svc->proto == ip6nxt &&
            __service_in_range(AF_INET6, &saddr, ports[0], &m->srange) &&
            __service_in_range(AF_INET6, &daddr, ports[1], &m->drange) &&
            (!idev || idev->id == mbuf->port) &&
            (!odev || odev->id == oif)
           ) {
            return svc;
        }
    }

    return NULL;
}

static struct dp_vs_service *
__dp_vs_service_match_get(int af, const struct rte_mbuf *mbuf, bool *outwall, lcoreid_t cid)
{
    if (af == AF_INET)
        return __dp_vs_service_match_get4(mbuf, outwall, cid);
    else if (af == AF_INET6)
        return __dp_vs_service_match_get6(mbuf, cid);
    else
        return NULL;
}

int dp_vs_match_parse(const char *srange, const char *drange,
                      const char *iifname, const char *oifname,
                      int af, struct dp_vs_match *match)
{
    int err;

    memset(match, 0, sizeof(*match));

    if (srange && strlen(srange)) {
        err = inet_addr_range_parse(srange, &match->srange, &match->af);
        if (err != EDPVS_OK)
            return err;
    }

    if (drange && strlen(drange)) {
        err = inet_addr_range_parse(drange, &match->drange, &match->af);
        if (err != EDPVS_OK)
            return err;
    }

    if (match->af && af && match->af != af)
        return EDPVS_INVAL;

    // no range param
    if (!match->af)
        match->af = af;

    snprintf(match->iifname, IFNAMSIZ, "%s", iifname ? : "");
    snprintf(match->oifname, IFNAMSIZ, "%s", oifname ? : "");

    return EDPVS_OK;
}

static struct dp_vs_service *
__dp_vs_service_match_find(int af, uint8_t proto, const struct dp_vs_match *match,
                       lcoreid_t cid)
{
    struct dp_vs_service *svc;

    if (!match || is_empty_match(match))
        return NULL;

    list_for_each_entry(svc, &dp_vs_svc_match_list[cid], m_list) {
        assert(svc->match);
        if (af == svc->af && proto == svc->proto &&
            memcmp(match, svc->match, sizeof(struct dp_vs_match)) == 0)
        {
            return svc;
        }
    }

    return NULL;
}

struct dp_vs_service *dp_vs_service_lookup(int af, uint16_t protocol,
                                        const union inet_addr *vaddr,
                                        uint16_t vport, uint32_t fwmark,
                                        const struct rte_mbuf *mbuf,
                                        const struct dp_vs_match *match,
                                        bool *outwall, lcoreid_t cid)
{
    struct dp_vs_service *svc = NULL;

    if (fwmark && (svc = __dp_vs_service_fwm_get(af, fwmark, cid)))
        goto out;

    if ((svc = __dp_vs_service_get(af, protocol, vaddr, vport, cid)))
        goto out;

    if (match && !is_empty_match(match))
        if ((svc = __dp_vs_service_match_find(af, protocol, match, cid)))
            goto out;

    if (mbuf) /* lowest priority */
        svc = __dp_vs_service_match_get(af, mbuf, outwall, cid);

out:
#ifdef CONFIG_DPVS_MBUF_DEBUG
    if (!svc && mbuf)
        dp_vs_mbuf_dump("found service failed.", af, mbuf);
#endif
    return svc;
}

struct dp_vs_service *dp_vs_vip_lookup(int af, uint16_t protocol,
                                       const union inet_addr *vaddr,
                                       lcoreid_t cid)
{
    struct dp_vs_service *svc;
    int hash;

    hash = dp_vs_service_hashkey(af, protocol, vaddr);
    if (hash < 0)
        return NULL;
    list_for_each_entry(svc, &dp_vs_svc_table[cid][hash], s_list) {
        if ((svc->af == af)
            && inet_addr_equal(af, &svc->addr, vaddr)
            && (svc->proto == protocol)) {
            /* HIT */
            return svc;
        }
    }

    return NULL;
}

void
dp_vs_service_bind(struct dp_vs_dest *dest, struct dp_vs_service *svc)
{
    rte_atomic32_inc(&svc->refcnt);
    dest->svc = svc;
}

void dp_vs_service_put(struct dp_vs_service *svc)
{
    if (!svc)
        return;

    if (rte_atomic32_dec_and_test(&svc->refcnt)) {
        if (svc->match)
            rte_free(svc->match);
        rte_free(svc);
        RTE_LOG(DEBUG, SERVICE, "%s: delete svc.\n", __func__);
    }
}

void dp_vs_service_unbind(struct dp_vs_dest *dest)
{
    if (!dest->svc)
        return;
    dp_vs_service_put(dest->svc);
    dest->svc = NULL;
}

static int dp_vs_service_add(struct dp_vs_service_conf *u,
                      struct dp_vs_service **svc_p,
                      lcoreid_t cid)
{
    int ret = 0;
    int size;
    struct dp_vs_scheduler *sched = NULL;
    struct dp_vs_service *svc = NULL;

    if (!u->fwmark && inet_is_addr_any(u->af, &u->addr)
        && !u->port && is_empty_match(&u->match)) {
        RTE_LOG(ERR, SERVICE, "%s: adding inval servive\n", __func__);
        return EDPVS_INVAL;
    }

    sched = dp_vs_scheduler_get(u->sched_name);
    if(sched == NULL) {
        RTE_LOG(ERR, SERVICE, "%s: scheduler not found.\n", __func__);
        return EDPVS_NOTEXIST;
    }

    size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct dp_vs_service));
    svc = rte_zmalloc("dp_vs_service", size, RTE_CACHE_LINE_SIZE);
    if(svc == NULL){
        RTE_LOG(ERR, SERVICE, "%s: no memory.\n", __func__);
        return EDPVS_NOMEM;
    }

    svc->af = u->af;
    svc->proto = u->protocol;
    svc->addr = u->addr;
    svc->port = u->port;
    svc->fwmark = u->fwmark;
    svc->flags = u->flags;
    svc->timeout = u->timeout;
    svc->conn_timeout = u->conn_timeout;
    svc->bps = u->bps;
    svc->limit_proportion = u->limit_proportion;
    svc->netmask = u->netmask;
    if (!is_empty_match(&u->match)) {
        svc->match = rte_zmalloc(NULL, sizeof(struct dp_vs_match),
                                 RTE_CACHE_LINE_SIZE);
        if (!svc->match) {
            ret = EDPVS_NOMEM;
            goto out_err;
        }

        *(svc->match) = u->match;
    }

    INIT_LIST_HEAD(&svc->laddr_list);
    svc->num_laddrs = 0;
    svc->laddr_curr = &svc->laddr_list;

    INIT_LIST_HEAD(&svc->dests);

    ret = dp_vs_bind_scheduler(svc, sched);
    if (ret)
        goto out_err;
    sched = NULL;

    rte_atomic16_inc(&dp_vs_num_services[cid]);

    ret = dp_vs_service_hash(svc, cid);
    if (ret != EDPVS_OK)
        return ret;
    rte_atomic32_set(&svc->refcnt, 1);

    *svc_p = svc;
    return EDPVS_OK;

out_err:
    if(svc != NULL) {
        if (svc->scheduler)
            dp_vs_unbind_scheduler(svc);
        if (svc->match)
            rte_free(svc->match);
        rte_free(svc);
    }
    return ret;
}

static int dp_vs_service_edit(struct dp_vs_service *svc, struct dp_vs_service_conf *u)
{
    struct dp_vs_scheduler *sched, *old_sched;
    int ret = 0;

    /*
     * Lookup the scheduler, by 'u->sched_name'
     */
    sched = dp_vs_scheduler_get(u->sched_name);
    if (sched == NULL) {
        RTE_LOG(ERR, SERVICE, "Scheduler dp_vs_%s not found\n", u->sched_name);
        return EDPVS_NOTEXIST;
    }
    old_sched = sched;

    if (u->af == AF_INET6 && (u->netmask < 1 || u->netmask > 128)) {
        ret = EDPVS_INVAL;
        goto out;
    }

    /*
     * Set the flags and timeout value
     */
    svc->flags = u->flags | DP_VS_SVC_F_HASHED;
    svc->timeout = u->timeout;
    svc->conn_timeout = u->conn_timeout;
    svc->netmask = u->netmask;
    svc->bps = u->bps;
    svc->limit_proportion = u->limit_proportion;

    old_sched = svc->scheduler;
    if (sched != old_sched) {
        /*
         * Unbind the old scheduler
         */
        if ((ret = dp_vs_unbind_scheduler(svc))) {
            old_sched = sched;
            goto out;
        }

        /*
         * Bind the new scheduler
         */
        if ((ret = dp_vs_bind_scheduler(svc, sched))) {
            /*
             * If ip_vs_bind_scheduler fails, restore the old
             * scheduler.
             * The main reason of failure is out of memory.
             *
             * The question is if the old scheduler can be
             * restored all the time. TODO: if it cannot be
             * restored some time, we must delete the service,
             * otherwise the system may crash.
             */
            dp_vs_bind_scheduler(svc, old_sched);
            old_sched = sched;
            goto out;
        }
    }

out:
    return ret;
}

static void __dp_vs_service_del(struct dp_vs_service *svc)
{
    struct dp_vs_dest *dest, *nxt;

    /* Count only IPv4 services for old get/setsockopt interface */
    rte_atomic16_dec(&dp_vs_num_services[rte_lcore_id()]);

    /* Unbind scheduler */
    dp_vs_unbind_scheduler(svc);

    dp_vs_laddr_flush(svc);

    dp_vs_blklst_flush(svc);

    dp_vs_whtlst_flush(svc);

    /*
     *    Unlink the whole destination list
     */
    list_for_each_entry_safe(dest, nxt, &svc->dests, n_list) {
        dp_vs_dest_unlink(svc, dest, 0);
        dp_vs_dest_put(dest);
    }

    /*
     *    Free the service if nobody refers to it
     */
    dp_vs_service_put(svc);
}

static int dp_vs_service_del(struct dp_vs_service *svc)
{
    if (svc == NULL)
        return EDPVS_NOTEXIST;

    /*
     * Unhash it from the service table
     */
    dp_vs_service_unhash(svc);

    /*
     * Wait until all the svc users go away.
     */
    __dp_vs_service_del(svc);

    return EDPVS_OK;
}

static int
dp_vs_service_copy(struct dp_vs_service_entry *dst, struct dp_vs_service *src)
{
    int err = 0;
    struct dp_vs_match *m;

    memset(dst, 0, sizeof(*dst));
    dst->af = src->af;
    dst->proto = src->proto;
    dst->addr = src->addr;
    dst->port = src->port;
    dst->fwmark = src->fwmark;
    snprintf(dst->sched_name, sizeof(dst->sched_name),
             "%s", src->scheduler->name);
    dst->flags = src->flags;
    dst->timeout = src->timeout;
    dst->conn_timeout = src->conn_timeout;
    dst->netmask = src->netmask;
    dst->num_dests = src->num_dests;
    dst->num_laddrs = src->num_laddrs;
    dst->cid = rte_lcore_id();

    err = dp_vs_stats_add(&dst->stats, &src->stats);

    m = src->match;
    if (!m)
        return err;

    inet_addr_range_dump(m->af, &m->srange, dst->srange, sizeof(dst->srange));
    inet_addr_range_dump(m->af, &m->drange, dst->drange, sizeof(dst->drange));

    snprintf(dst->iifname, sizeof(dst->iifname), "%s", m->iifname);
    snprintf(dst->oifname, sizeof(dst->oifname), "%s", m->oifname);

    return err;
}

static int dp_vs_service_get_entries(int num_services,
                                     struct dp_vs_get_services *uptr,
                                     lcoreid_t cid)
{
    int idx, count = 0;
    struct dp_vs_service *svc;
    int ret = 0;

    uptr->cid = cid;
    uptr->num_services = num_services;
    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_table[cid][idx], s_list){
            if (count >= num_services)
                goto out;
            ret = dp_vs_service_copy(&uptr->entrytable[count], svc);
            if (ret != EDPVS_OK)
                goto out;
            count++;
        }
    }

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_fwm_table[cid][idx], f_list) {
            if (count >= num_services)
                goto out;
            ret = dp_vs_service_copy(&uptr->entrytable[count], svc);
            if (ret != EDPVS_OK)
                goto out;
            count++;
        }
    }

    list_for_each_entry(svc, &dp_vs_svc_match_list[cid], m_list) {
        if (count >= num_services)
            goto out;
        ret = dp_vs_service_copy(&uptr->entrytable[count], svc);
        if (ret != EDPVS_OK)
            goto out;
        count++;
    }

    if (count < num_services)
        ret = EDPVS_INVAL;
out:
    return ret;
}

static int dp_vs_services_flush(lcoreid_t cid)
{
    int idx;
    struct dp_vs_service *svc, *nxt;

    /*
     * Flush the service table hashed by <protocol,addr,port>
     */
    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry_safe(svc, nxt, &dp_vs_svc_table[cid][idx],
                     s_list) {
            dp_vs_service_del(svc);
        }
    }

    /*
     * Flush the service table hashed by fwmark
     */
    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry_safe(svc, nxt,
                     &dp_vs_svc_fwm_table[cid][idx], f_list) {
            dp_vs_service_del(svc);
        }
    }

    list_for_each_entry_safe(svc, nxt,
                    &dp_vs_svc_match_list[cid], m_list) {
            dp_vs_service_del(svc);
    }

    return EDPVS_OK;
}

static int dp_vs_service_zero(struct dp_vs_service *svc)
{
    struct dp_vs_dest *dest;

    list_for_each_entry(dest, &svc->dests, n_list) {
        dp_vs_stats_clear(&dest->stats);
    }
    dp_vs_stats_clear(&svc->stats);
    return EDPVS_OK;
}

static int dp_vs_services_zero(lcoreid_t cid)
{
    int idx;
    struct dp_vs_service *svc;

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_table[cid][idx], s_list) {
            dp_vs_service_zero(svc);
        }
    }

    for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
        list_for_each_entry(svc, &dp_vs_svc_fwm_table[cid][idx], f_list) {
            dp_vs_service_zero(svc);
        }
    }

    list_for_each_entry(svc, &dp_vs_svc_match_list[cid], m_list) {
        dp_vs_service_zero(svc);
    }

    dp_vs_estats_clear();
    return EDPVS_OK;
}


/*CONTROL PLANE*/
static int dp_vs_copy_usvc_compat(struct dp_vs_service_conf *conf,
                                  struct dp_vs_service_user *user)
{
    int err;
    conf->af = user->af;
    conf->protocol = user->proto;
    conf->addr = user->addr;
    conf->port = user->port;
    conf->fwmark = user->fwmark;

    /* Deep copy of sched_name is not needed here */
    conf->sched_name = user->sched_name;

    conf->flags = user->flags;
    conf->timeout = user->timeout;
    conf->conn_timeout = user->conn_timeout;
    conf->netmask = user->netmask;
    conf->bps = user->bps;
    conf->limit_proportion = user->limit_proportion;

    if (user->flags & DP_VS_SVC_F_MATCH) {
        err = dp_vs_match_parse(user->srange, user->drange,
                                user->iifname, user->oifname,
                                user->af, &conf->match);
        if (err != EDPVS_OK)
            return err;
        if (conf->match.af && !conf->af)
            conf->af = conf->match.af;
        if ((conf->match.af != AF_INET) && (conf->match.af != AF_INET6))
            return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static void dp_vs_copy_udest_compat(struct dp_vs_dest_conf *udest,
                                    struct dp_vs_dest_user *udest_compat)
{
    udest->af         = udest_compat->af;
    udest->addr       = udest_compat->addr;
    udest->port       = udest_compat->port;
    udest->fwdmode    = udest_compat->conn_flags;//make sure fwdmode and conn_flags are the same
    udest->conn_flags = udest_compat->conn_flags;
    udest->weight     = udest_compat->weight;
    udest->max_conn   = udest_compat->max_conn;
    udest->min_conn   = udest_compat->min_conn;
}

static int gratuitous_arp_send_vip(struct in_addr *vip)
{
    struct route_entry *local_route;

    local_route = route_out_local_lookup(vip->s_addr);
    if(local_route){
        neigh_gratuitous_arp(&local_route->dest, local_route->port);
        route4_put(local_route);
        return EDPVS_OK;
    }
    return EDPVS_NOTEXIST;
}

static inline int set_opt_so2msg(sockoptid_t opt)
{
    return opt - SOCKOPT_SVC_BASE + MSG_TYPE_SVC_SET_BASE;
}

static int svc_msg_seq(void)
{
    static uint32_t seq = 0;

    return seq++;
}

static int dp_vs_service_set(sockoptid_t opt, const void *user, size_t len)
{
    int ret;
    unsigned char arg[MAX_ARG_LEN];
    struct dp_vs_service_user *usvc_compat;
    struct dp_vs_service_conf usvc;
    struct dp_vs_service *svc = NULL;
    struct dp_vs_dest_user *udest_compat;
    struct dp_vs_dest_conf udest;
    struct in_addr *vip;
    lcoreid_t cid = rte_lcore_id();

    if (opt == DPVS_SO_SET_GRATARP && cid == rte_get_main_lcore()){
        vip = (struct in_addr *)user;
        return gratuitous_arp_send_vip(vip);
    }

    // send to slave core
    if (cid == rte_get_main_lcore()) {
        struct dpvs_msg *msg;

        msg = msg_make(set_opt_so2msg(opt), svc_msg_seq(), DPVS_MSG_MULTICAST, cid, len, user);
        if (!msg)
            return EDPVS_NOMEM;

        ret = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
        /* go on in master core, not return */
        if (ret != EDPVS_OK)
            RTE_LOG(ERR, SERVICE, "[%s] fail to send multicast message\n", __func__);
        msg_destroy(&msg);
    }

    if (opt == DPVS_SO_SET_FLUSH)
        return dp_vs_services_flush(cid);

    memcpy(arg, user, len);
    usvc_compat = (struct dp_vs_service_user *)arg;
    udest_compat = (struct dp_vs_dest_user *)(usvc_compat + 1);

    memset(&usvc, 0, sizeof(usvc));
    ret = dp_vs_copy_usvc_compat(&usvc, usvc_compat);
    if (ret != EDPVS_OK)
        return ret;

    if (opt == DPVS_SO_SET_ZERO) {
        if(!inet_is_addr_any(usvc.af, &usvc.addr) &&
           !usvc.fwmark && !usvc.port &&
           is_empty_match(&usvc.match)
          ) {
            return dp_vs_services_zero(cid);
        }
    }

    if (usvc.protocol != IPPROTO_TCP && usvc.protocol != IPPROTO_UDP &&
        usvc.protocol != IPPROTO_ICMP && usvc.protocol != IPPROTO_ICMPV6) {
        RTE_LOG(ERR, SERVICE, "%s: protocol not support.\n", __func__);
        return EDPVS_INVAL;
    }

    if (!inet_is_addr_any(usvc.af, &usvc.addr) || usvc.port)
        svc = __dp_vs_service_get(usvc.af, usvc.protocol,
                                  &usvc.addr, usvc.port, cid);
    else if (usvc.fwmark)
        svc = __dp_vs_service_fwm_get(usvc.af, usvc.fwmark, cid);
    else if (!is_empty_match(&usvc.match))
        svc = __dp_vs_service_match_find(usvc.af, usvc.protocol, &usvc.match, cid);
    else {
        RTE_LOG(ERR, SERVICE, "%s: empty service.\n", __func__);
        return EDPVS_INVAL;
    }

    if(opt != DPVS_SO_SET_ADD &&
            (svc == NULL || svc->proto != usvc.protocol)){
        return EDPVS_INVAL;
    }

    switch(opt){
        case DPVS_SO_SET_ADD:
            if(svc != NULL)
                ret = EDPVS_EXIST;
            else
                ret = dp_vs_service_add(&usvc, &svc, cid);
            break;
        case DPVS_SO_SET_EDIT:
            ret = dp_vs_service_edit(svc, &usvc);
            break;
        case DPVS_SO_SET_DEL:
            ret = dp_vs_service_del(svc);
            break;
        case DPVS_SO_SET_ZERO:
            ret = dp_vs_service_zero(svc);
            break;
        case DPVS_SO_SET_ADDDEST:
            dp_vs_copy_udest_compat(&udest, udest_compat);
            ret = dp_vs_dest_add(svc, &udest);
            break;
        case DPVS_SO_SET_EDITDEST:
            dp_vs_copy_udest_compat(&udest, udest_compat);
            ret = dp_vs_dest_edit(svc, &udest);
            break;
        case DPVS_SO_SET_DELDEST:
            dp_vs_copy_udest_compat(&udest, udest_compat);
            ret = dp_vs_dest_del(svc, &udest);
            break;
        default:
            ret = EDPVS_INVAL;
    }

    return ret;
}

/*
 * for example : SOCKOPT_SVC_BASE is 200, SOCKOPT_SVC_GET_CMD_MAX is 204,
 * old_opt 205 means core 1 get opt 200
 */
static inline int opt2cpu(sockoptid_t old_opt, sockoptid_t *new_opt, lcoreid_t *cid)
{
    assert(old_opt >= SOCKOPT_SVC_BASE);
    assert(old_opt <= SOCKOPT_SVC_MAX);
    int index = (old_opt - SOCKOPT_SVC_BASE)/(SOCKOPT_SVC_GET_CMD_MAX - SOCKOPT_SVC_BASE + 1);
    if (index >= g_lcore_num) {
        return -1;
    }
    *new_opt = (old_opt - SOCKOPT_SVC_BASE)%(SOCKOPT_SVC_GET_CMD_MAX - SOCKOPT_SVC_BASE + 1)
               + SOCKOPT_SVC_BASE;
    *cid = g_lcore_index[index];
    assert(*cid >= 0 && *cid < DPVS_MAX_LCORE);
    return 0;
}

/* copy service/dest/stats */
static int dp_vs_services_copy_percore_stats(struct dp_vs_get_services *master_svcs,
                                             struct dp_vs_get_services *slave_svcs)
{
    int i;
    if (master_svcs->num_services != slave_svcs->num_services)
        return EDPVS_INVAL;
    for (i = 0; i < master_svcs->num_services; i++)
        dp_vs_stats_add(&master_svcs->entrytable[i].stats, &slave_svcs->entrytable[i].stats);
    return EDPVS_OK;
}

//dest should not be changed during get msg
static int dp_vs_dests_copy_percore_stats(struct dp_vs_get_dests *master_dests,
                                          struct dp_vs_get_dests *slave_dests)
{
    int i;
    if (master_dests->num_dests != slave_dests->num_dests)
        return EDPVS_INVAL;
    for (i = 0; i < master_dests->num_dests; i++) {
        master_dests->entrytable[i].max_conn += slave_dests->entrytable[i].max_conn;
        master_dests->entrytable[i].min_conn += slave_dests->entrytable[i].min_conn;
        master_dests->entrytable[i].actconns += slave_dests->entrytable[i].actconns;
        master_dests->entrytable[i].inactconns += slave_dests->entrytable[i].inactconns;
        master_dests->entrytable[i].persistconns += slave_dests->entrytable[i].persistconns;
        dp_vs_stats_add(&master_dests->entrytable[i].stats, &slave_dests->entrytable[i].stats);
    }

    return EDPVS_OK;
}

static int dp_vs_services_get_uc_cb(struct dpvs_msg *msg)
{
    lcoreid_t cid = rte_lcore_id();
    size_t size;
    struct dp_vs_get_services *get, *output;
    int ret;

    /* service may be changed */
    get = (struct dp_vs_get_services *)msg->data;
    if (get->num_services != rte_atomic16_read(&dp_vs_num_services[cid])) {
        RTE_LOG(ERR, SERVICE, "%s: svc number %d not match %d in cid=%d.\n",
        __func__, get->num_services, rte_atomic16_read(&dp_vs_num_services[cid]), cid);
        return EDPVS_INVAL;
    }

    size = sizeof(*get) + sizeof(struct dp_vs_service_entry) * get->num_services;
    output = msg_reply_alloc(size);
    if (output == NULL)
        return EDPVS_NOMEM;
    ret = dp_vs_service_get_entries(get->num_services, output, cid);
    if (ret != EDPVS_OK) {
        msg_reply_free(output);
        return ret;
    }
    msg->reply.len = size;
    msg->reply.data = (void *)output;
    return EDPVS_OK;
}

static struct dp_vs_service *
dp_vs_service_get_lcore(const struct dp_vs_service_entry *entry,
                                              lcoreid_t cid)
{
    struct dp_vs_service *svc = NULL;
    int ret;

    if(entry->fwmark)
        svc = __dp_vs_service_fwm_get(AF_INET, entry->fwmark, cid);
    else if (!inet_is_addr_any(entry->af, &entry->addr) || entry->port)
        svc = __dp_vs_service_get(entry->af, entry->proto,
                                  &entry->addr, entry->port, cid);
    else {
        struct dp_vs_match match;

        ret = dp_vs_match_parse(entry->srange, entry->drange,
                                entry->iifname, entry->oifname,
                                entry->af, &match);
        if (ret != EDPVS_OK)
            return NULL;

        if (!is_empty_match(&match)) {
            svc = __dp_vs_service_match_find(match.af, entry->proto,
                                         &match, cid);
        }
    }

    return svc;
}

static int dp_vs_service_get_uc_cb(struct dpvs_msg *msg)
{
    lcoreid_t cid = rte_lcore_id();
    struct dp_vs_service_entry *entry;
    struct dp_vs_service *svc;
    int ret, size;

    entry = (struct dp_vs_service_entry *)msg->data;
    svc = dp_vs_service_get_lcore(entry, cid);
    if (!svc)
        return EDPVS_NOTEXIST;

    size = sizeof(struct dp_vs_service_entry);
    entry = msg_reply_alloc(size);
    if (entry == NULL)
        return EDPVS_NOMEM;

    ret = dp_vs_service_copy(entry, svc);
    if (ret != EDPVS_OK) {
        msg_reply_free(entry);
        return ret;
    }
    msg->reply.len = size;
    msg->reply.data = (void *)entry;
    return EDPVS_OK;
}

static int dp_vs_dests_get_uc_cb(struct dpvs_msg *msg)
{
    lcoreid_t cid = rte_lcore_id();
    int ret;
    size_t size;
    struct dp_vs_get_dests *get, *output;
    struct dp_vs_service *svc;
    struct dp_vs_service_entry entry; // to get svc

    memset(&entry, 0, sizeof(entry));
    get = (struct dp_vs_get_dests *)msg->data;
    entry.addr    = get->addr;
    entry.af      = get->af;
    entry.fwmark  = get->fwmark;
    entry.port    = get->port;
    entry.proto   = get->proto;
    rte_memcpy(entry.srange, get->srange, sizeof(get->srange));
    rte_memcpy(entry.drange, get->drange, sizeof(get->drange));
    rte_memcpy(entry.iifname, get->iifname, sizeof(get->iifname));
    rte_memcpy(entry.oifname, get->oifname, sizeof(get->oifname));

    svc = dp_vs_service_get_lcore(&entry, cid);
    if (!svc)
        return EDPVS_NOTEXIST;
    if (svc->num_dests != get->num_dests) {
        RTE_LOG(ERR, SERVICE, "%s: dests number not match in cid=%d.\n", __func__, cid);
        return EDPVS_INVAL;
    }

    size = sizeof(*get) + sizeof(struct dp_vs_dest_entry) * (svc->num_dests);
    output = msg_reply_alloc(size);
    if (output == NULL)
        return EDPVS_NOMEM;
    rte_memcpy(output, get, sizeof(*get));
    ret = dp_vs_dest_get_entries(svc, output);
    if (ret != EDPVS_OK) {
        msg_reply_free(output);
        return ret;
    }

    msg->reply.len = size;
    msg->reply.data = (void *)output;
    return EDPVS_OK;
}

static int dp_vs_service_get(sockoptid_t opt, const void *user, size_t len, void **out, size_t *outlen)
{
    int ret = 0;
    uint8_t num_lcores = 0;
    lcoreid_t cid;
    sockoptid_t new_opt;

    netif_get_slave_lcores(&num_lcores, NULL);
    if (opt2cpu(opt, &new_opt, &cid) < 0) {
        return EDPVS_INVAL;
    }
    if (new_opt > SOCKOPT_SVC_MAX)
        return EDPVS_INVAL;

    switch (new_opt){
        case DPVS_SO_GET_VERSION:
            {
                char *buf = rte_zmalloc("info",64,0);
                if (unlikely(NULL == buf))
                    return EDPVS_NOMEM;
                sprintf(buf,"DPDK-FULLNAT Server version 1.1.4 (size=0)");
                *out = buf;
                *outlen = 64;
                return EDPVS_OK;
            }
        case DPVS_SO_GET_INFO:
            {
                struct dp_vs_getinfo *info;
                info = rte_zmalloc("info", sizeof(struct dp_vs_getinfo), 0);
                if (unlikely(NULL == info))
                    return EDPVS_NOMEM;
                info->version = 0;
                info->size = 0;
                info->num_services = rte_atomic16_read(&dp_vs_num_services[cid]);
                info->num_lcores = num_lcores;
                *out = info;
                *outlen = sizeof(struct dp_vs_getinfo);
                return EDPVS_OK;
            }
        case DPVS_SO_GET_SERVICES:
            {
                struct dp_vs_get_services *get, *get_msg, *output;
                struct dpvs_msg *msg, *cur;
                struct dpvs_multicast_queue *reply = NULL;
                int size;

                get = (struct dp_vs_get_services *)user;
                size = sizeof(*get) + \
                       sizeof(struct dp_vs_service_entry) * (get->num_services);
                if (len != sizeof(*get)){
                    *outlen = 0;
                    return EDPVS_INVAL;
                }

                /* get slave core svc */
                msg = msg_make(MSG_TYPE_SVC_GET_SERVICES, 0, DPVS_MSG_MULTICAST, rte_lcore_id(),
                               sizeof(*get), user);
                if (!msg) {
                    return EDPVS_NOMEM;
                }

                ret = multicast_msg_send(msg, 0, &reply);
                if (ret != EDPVS_OK) {
                    msg_destroy(&msg);
                    RTE_LOG(ERR, SERVICE, "%s: send message fail.\n", __func__);
                    return EDPVS_MSG_FAIL;
                }

                if (cid == rte_get_main_lcore()) {
                    output = rte_zmalloc("get_services", size, 0);
                    if (unlikely(NULL == output)) {
                        msg_destroy(&msg);
                        return EDPVS_NOMEM;
                    }
                    rte_memcpy(output, get, sizeof(*get));
                    ret = dp_vs_service_get_entries(get->num_services, output, cid);
                    if (ret != EDPVS_OK) {
                        msg_destroy(&msg);
                        rte_free(output);
                        return ret;
                    }
                    list_for_each_entry(cur, &reply->mq, mq_node) {
                        get_msg = (struct dp_vs_get_services *)(cur->data);
                        ret = dp_vs_services_copy_percore_stats(output, get_msg);
                        if (ret != EDPVS_OK) {
                            msg_destroy(&msg);
                            rte_free(output);
                            return ret;
                        }
                    }
                    *out = output;
                    *outlen = size;
                    msg_destroy(&msg);
                    return EDPVS_OK;
                } else {
                    list_for_each_entry(cur, &reply->mq, mq_node) {
                        get_msg = (struct dp_vs_get_services *)(cur->data);
                        if (get_msg->cid == cid) {
                            output = rte_zmalloc("get_services", size, 0);
                            if (unlikely(NULL == output)) {
                                msg_destroy(&msg);
                                return EDPVS_NOMEM;
                            }
                            rte_memcpy(output, get_msg, size);
                            *out = output;
                            *outlen = size;
                            msg_destroy(&msg);
                            return EDPVS_OK;
                        }
                    }
                    RTE_LOG(ERR, SERVICE, "%s: find no services for cid=%d.\n", __func__, cid);
                    msg_destroy(&msg);
                    return EDPVS_NOTEXIST;
                }
            }
        case DPVS_SO_GET_SERVICE:
            {
                struct dp_vs_service_entry *entry, *get_msg, *output;
                struct dpvs_msg *msg, *cur;
                struct dpvs_multicast_queue *reply = NULL;
                struct dp_vs_service *svc = NULL;

                entry = (struct dp_vs_service_entry *)user;

                /* get slave core svc */
                msg = msg_make(MSG_TYPE_SVC_GET_SERVICE, 0, DPVS_MSG_MULTICAST, rte_lcore_id(),
                               sizeof(struct dp_vs_service_entry), user);
                if (!msg)
                    return EDPVS_NOMEM;

                ret = multicast_msg_send(msg, 0, &reply);
                if (ret != EDPVS_OK) {
                    msg_destroy(&msg);
                    RTE_LOG(ERR, SERVICE, "%s: send message fail.\n", __func__);
                    return EDPVS_MSG_FAIL;
                }

                if (cid == rte_get_main_lcore()) {
                    svc = dp_vs_service_get_lcore(entry, cid);
                    if (!svc) {
                        msg_destroy(&msg);
                        return EDPVS_NOTEXIST;
                    }

                    output = rte_zmalloc("get_service",
                                          sizeof(struct dp_vs_service_entry), 0);
                    if (output == NULL) {
                        msg_destroy(&msg);
                        return EDPVS_NOTEXIST;
                    }
                    memcpy(output, entry, sizeof(struct dp_vs_service_entry));
                    ret = dp_vs_service_copy(output, svc);
                    if (ret != EDPVS_OK) {
                        msg_destroy(&msg);
                        rte_free(output);
                        return ret;
                    }

                    list_for_each_entry(cur, &reply->mq, mq_node) {
                        get_msg = (struct dp_vs_service_entry *)(cur->data);
                        ret = dp_vs_stats_add(&output->stats, &get_msg->stats);
                        if (ret != EDPVS_OK) {
                            msg_destroy(&msg);
                            rte_free(output);
                            return ret;
                        }
                    }
                    *out = output;
                    *outlen = sizeof(struct dp_vs_service_entry);
                    msg_destroy(&msg);
                    return EDPVS_OK;
                } else {
                    output = rte_zmalloc("get_service",
                                         sizeof(struct dp_vs_service_entry), 0);
                    if (!output) {
                        msg_destroy(&msg);
                        return EDPVS_NOTEXIST;
                    }
                    list_for_each_entry(cur, &reply->mq, mq_node) {
                        get_msg = (struct dp_vs_service_entry *)(cur->data);
                        if (cid == get_msg->cid) {
                            rte_memcpy(output, get_msg, sizeof(struct dp_vs_service_entry));
                            *out = output;
                            *outlen = sizeof(struct dp_vs_service_entry);
                            msg_destroy(&msg);
                            return EDPVS_OK;
                        }
                    }
                    RTE_LOG(ERR, SERVICE, "%s: find no service for cid=%d.\n", __func__, cid);
                    msg_destroy(&msg);
                    rte_free(output);
                    return EDPVS_NOTEXIST;
                }
            }
        case DPVS_SO_GET_DESTS:
            {
                struct dp_vs_service *svc = NULL;
                struct dp_vs_get_dests *get, *get_msg, *output;
                struct dpvs_msg *msg, *cur;
                struct dpvs_multicast_queue *reply = NULL;
                struct dp_vs_service_entry entry; // to get svc
                int size;
                get = (struct dp_vs_get_dests *)user;
                size = sizeof(*get) + sizeof(struct dp_vs_dest_entry) * get->num_dests;
                if(len != sizeof(*get)){
                    *outlen = 0;
                    return EDPVS_INVAL;
                }

                entry.addr    = get->addr;
                entry.af      = get->af;
                entry.fwmark  = get->fwmark;
                entry.port    = get->port;
                entry.proto   = get->proto;
                rte_memcpy(entry.srange, get->srange, sizeof(get->srange));
                rte_memcpy(entry.drange, get->drange, sizeof(get->drange));
                rte_memcpy(entry.iifname, get->iifname, sizeof(get->iifname));
                rte_memcpy(entry.oifname, get->oifname, sizeof(get->oifname));

                /* get slave core svc */
                msg = msg_make(MSG_TYPE_SVC_GET_DESTS, 0, DPVS_MSG_MULTICAST, rte_lcore_id(),
                               sizeof(struct dp_vs_get_dests), user);
                if (!msg)
                    return EDPVS_NOMEM;

                ret = multicast_msg_send(msg, 0, &reply);
                if (ret != EDPVS_OK) {
                    msg_destroy(&msg);
                    RTE_LOG(ERR, SERVICE, "%s: send message fail.\n", __func__);
                    return EDPVS_MSG_FAIL;
                }

                if (cid == rte_get_main_lcore()) {
                    svc = dp_vs_service_get_lcore(&entry, cid);
                    if (!svc) {
                        msg_destroy(&msg);
                        return EDPVS_NOTEXIST;
                    }
                    if (svc->num_dests != get->num_dests) {
                        RTE_LOG(ERR, SERVICE, "%s: dests number not match in cid=%d.\n", __func__, cid);
                        msg_destroy(&msg);
                        return EDPVS_INVAL;
                    }
                    output = rte_zmalloc("get_dests", size, 0);
                    if (!output) {
                        msg_destroy(&msg);
                        return EDPVS_NOMEM;
                    }
                    rte_memcpy(output, get, sizeof(get));
                    ret = dp_vs_dest_get_entries(svc, output);
                    if (ret != EDPVS_OK) {
                        msg_destroy(&msg);
                        rte_free(output);
                        return ret;
                    }

                    list_for_each_entry(cur, &reply->mq, mq_node) {
                        get_msg = (struct dp_vs_get_dests *)(cur->data);
                        ret = dp_vs_dests_copy_percore_stats(output, get_msg);
                        if (ret != EDPVS_OK) {
                            msg_destroy(&msg);
                            rte_free(output);
                            return ret;
                        }
                    }
                    *out = output;
                    *outlen = size;
                    msg_destroy(&msg);
                    return EDPVS_OK;
                } else {
                    output = rte_zmalloc("get_dests", size, 0);
                    if (!output) {
                        msg_destroy(&msg);
                        return EDPVS_NOMEM;
                    }
                    list_for_each_entry(cur, &reply->mq, mq_node) {
                        get_msg = (struct dp_vs_get_dests *)(cur->data);
                        if (cid == get_msg->cid) {
                            rte_memcpy(output, get_msg, size);
                            *out = output;
                            *outlen = size;
                            msg_destroy(&msg);
                            return EDPVS_OK;
                        }
                    }
                    RTE_LOG(ERR, SERVICE, "%s: find no dests for cid=%d.\n", __func__, cid);
                    msg_destroy(&msg);
                    rte_free(output);
                    return EDPVS_NOTEXIST;
                }
            }
        default:
            return EDPVS_INVAL;
    }
}

struct dpvs_sockopts sockopts_svc = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SVC_BASE,
    .set_opt_max    = SOCKOPT_SVC_SET_CMD_MAX,
    .set            = dp_vs_service_set,
    .get_opt_min    = SOCKOPT_SVC_BASE,
    .get_opt_max    = SOCKOPT_SVC_MAX,
    .get            = dp_vs_service_get,
};

static int flush_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_service_set(DPVS_SO_SET_FLUSH, msg->data, msg->len);
}

static int zero_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_service_set(DPVS_SO_SET_ZERO, msg->data, msg->len);
}

static int add_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_service_set(DPVS_SO_SET_ADD, msg->data, msg->len);
}

static int edit_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_service_set(DPVS_SO_SET_EDIT, msg->data, msg->len);
}

static int del_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_service_set(DPVS_SO_SET_DEL, msg->data, msg->len);
}

static int adddest_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_service_set(DPVS_SO_SET_ADDDEST, msg->data, msg->len);
}

static int editdest_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_service_set(DPVS_SO_SET_EDITDEST, msg->data, msg->len);
}

static int deldest_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_service_set(DPVS_SO_SET_DELDEST, msg->data, msg->len);
}

int dp_vs_service_init(void)
{
    int idx, cid, err;
    struct dpvs_msg_type msg_type;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        for (idx = 0; idx < DP_VS_SVC_TAB_SIZE; idx++) {
            INIT_LIST_HEAD(&dp_vs_svc_table[cid][idx]);
            INIT_LIST_HEAD(&dp_vs_svc_fwm_table[cid][idx]);
        }
        INIT_LIST_HEAD(&dp_vs_svc_match_list[cid]);
        rte_atomic16_init(&dp_vs_num_services[cid]);
    }
    dp_vs_dest_init();
    sockopt_register(&sockopts_svc);

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_SVC_SET_FLUSH;
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
    msg_type.type   = MSG_TYPE_SVC_SET_ZERO;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = zero_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_SVC_SET_ADD;
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
    msg_type.type   = MSG_TYPE_SVC_SET_EDIT;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = edit_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_SVC_SET_DEL;
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
    msg_type.type   = MSG_TYPE_SVC_SET_ADDDEST;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = adddest_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_SVC_SET_EDITDEST;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = editdest_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_SVC_SET_DELDEST;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = deldest_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_SVC_GET_SERVICES;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_LOW;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = dp_vs_services_get_uc_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_SVC_GET_SERVICE;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_LOW;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = dp_vs_service_get_uc_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_SVC_GET_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_LOW;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = dp_vs_dests_get_uc_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    return EDPVS_OK;
}

int dp_vs_service_term(void)
{
    int cid;
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        dp_vs_services_flush(cid);
    }
    dp_vs_dest_term();
    return EDPVS_OK;
}
