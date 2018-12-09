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

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "ipvs/service.h"
#include "ipvs/acl.h"
#include "ipvs/proto.h"
#include "netif.h"
#include "list.h"
#include "inet.h"
#include "ctrl.h"
#include "math.h"
#include "dpdk.h"
#include "ipvs/ipvs.h"

#define DPVS_ACL_TAB_BITS    16
#define DPVS_ACL_TAB_SIZE    (1 << DPVS_ACL_TAB_BITS)
#define DPVS_ACL_TAB_MASK    (DPVS_ACL_TAB_SIZE - 1)

static int dp_vs_acl_parse(const char *srange, const char *drange,
                           int rule, int max_conn,
                           struct dp_vs_acl *acl)
{
    int err;

    if (!srange || !drange || !acl) {
        return EDPVS_INVAL;
    }

    memset(acl, 0, sizeof(*acl));
    if (srange && strlen(srange)) {
        err = inet_addr_range_parse(srange, &acl->srange, &acl->af);
        if (err != EDPVS_OK) {
            return err;
        }
    }

    if (drange && strlen(drange)) {
        err = inet_addr_range_parse(drange, &acl->drange, &acl->af);
        if (err != EDPVS_OK) {
            return err;
        }
    }

    acl->rule = rule;
    acl->max_conn= max_conn;

    return EDPVS_OK;
}

static bool dp_vs_acl_equal(struct dp_vs_acl *acl1, struct dp_vs_acl *acl2)
{
    return acl1->af == acl2->af &&
           !memcmp(&acl1->srange, &acl2->srange, sizeof(struct inet_addr_range)) &&
           !memcmp(&acl1->drange, &acl2->drange, sizeof(struct inet_addr_range));
}

static struct dp_vs_acl *dp_vs_acl_find(int af,
                                        const char *srange,
                                        const char *drange,
                                        int rule, int max_conn,
                                        struct dp_vs_service *svc)
{
    struct dp_vs_acl acl, *acl_iter;

    int err = dp_vs_acl_parse(srange, drange, rule, max_conn, &acl);
    if ( err != EDPVS_OK) {
        return NULL;
    }

    list_for_each_entry(acl_iter, &svc->acl_list, list) {
        if (dp_vs_acl_equal(acl_iter, &acl)) {
            return acl_iter;
        }
    }
    return NULL;
}

static inline bool judge_ip_betw(int af, const union inet_addr *addr,
                                 const union inet_addr *min_addr,
                                 const union inet_addr *max_addr)
{
    if (!addr || !min_addr || !max_addr) {
        return false;
    }

    if (inet_is_addr_any(af, min_addr) || inet_is_addr_any(af, max_addr)) {
        return true;
    }

    if (AF_INET == af) {
        uint32_t laddr = addr->in.s_addr;
        uint32_t min   = min_addr->in.s_addr;
        uint32_t max   = max_addr->in.s_addr;
        return ((laddr >= min) && laddr <= max);
    } else {
        // ipv6, fix me, pass now
    }
    return true;
}

static inline bool judge_port_betw(uint16_t port, uint16_t min_port,
                                   uint16_t max_port)
{
/* change to DEBUG when changed to dpdk 17.11, fix me */
#ifdef CONFIG_DPVS_ACL_DEBUG
    RTE_LOG(ERR, ACL, "flow port = %d, judge min port = %d, max port = %d.\n",
                port, min_port, max_port);
#endif

    if (!port || !min_port || !max_port) {
        return true;
    }

    return ((port >= min_port) && (port <= max_port));
}

static struct dp_vs_acl *dp_vs_acl_lookup(int af,
                                          const union inet_addr *saddr,
                                          const union inet_addr *daddr,
                                          uint16_t sport, uint16_t dport,
                                          struct dp_vs_service *svc)
{
    if (!svc) {
        return NULL;
    }

    /* port of srange was network byte order */
    struct dp_vs_acl *acl;
    list_for_each_entry(acl, &svc->acl_list, list) {
        if (af == acl->af &&
            judge_ip_betw(af, saddr, &acl->srange.min_addr,
                                     &acl->srange.max_addr) &&
            judge_ip_betw(af, daddr, &acl->drange.min_addr,
                                     &acl->drange.max_addr) &&
            judge_port_betw(sport, ntohs(acl->srange.min_port),
                                   ntohs(acl->srange.max_port)) &&
            judge_port_betw(dport, ntohs(acl->drange.min_port),
                                   ntohs(acl->drange.max_port))) {
            return acl;
        }
    }

    return NULL;
}

static int dp_vs_acl_add(int af,
                         const char *srange, const char *drange,
                         int rule, int max_conn,
                         struct dp_vs_service *svc)
{
    struct dp_vs_acl *new_acl;

    if (!svc || !srange || !drange) {
        return EDPVS_INVAL;
    }

    new_acl = rte_zmalloc("dp_vs_acl", sizeof(*new_acl), 0);
    if (!new_acl) {
        return EDPVS_NOMEM;
    }

    if (dp_vs_acl_parse(srange, drange, rule, max_conn, new_acl) != EDPVS_OK) {
        rte_free(new_acl);
        return EDPVS_INVAL;
    }

    rte_rwlock_write_lock(&svc->acl_lock);
    if (dp_vs_acl_find(af, srange, drange, rule, max_conn, svc) != NULL) {
        rte_rwlock_write_unlock(&svc->acl_lock);
        rte_free(new_acl);
        return EDPVS_EXIST;
    }
    list_add_tail(&new_acl->list, &svc->acl_list);
    ++svc->num_acls;
    rte_rwlock_write_unlock(&svc->acl_lock);

    return EDPVS_OK;
}

static int dp_vs_acl_del(int af,
                         const char *srange, const char *drange,
                         int rule, int max_conn,
                         struct dp_vs_service *svc)
{
    struct dp_vs_acl *acl;

    if (!svc || !srange || !drange) {
        return EDPVS_INVAL;
    }

    rte_rwlock_write_lock(&svc->acl_lock);
    acl = dp_vs_acl_find(af, srange, drange, rule, max_conn, svc);
    if (!acl) {
        rte_rwlock_write_unlock(&svc->acl_lock);
        return EDPVS_NOTEXIST;
    }
    list_del(&acl->list);
    rte_free(acl);
    --svc->num_acls;
    rte_rwlock_write_unlock(&svc->acl_lock);

    return EDPVS_OK;
}

int dp_vs_acl_flush(struct dp_vs_service *svc)
{
    if (!svc) {
        return EDPVS_INVAL;
    }
    struct dp_vs_acl *acl_curr, *acl_next;

    rte_rwlock_write_lock(&svc->acl_lock);
    list_for_each_entry_safe(acl_curr, acl_next, &svc->acl_list, list) {
        list_del(&acl_curr->list);
        rte_free(acl_curr);
    }
    rte_rwlock_write_unlock(&svc->acl_lock);

    return EDPVS_OK;
}

int dp_vs_acl_flushall(void)
{
    struct dp_vs_service *svc;
    struct dp_vs_acl *acl_curr, *acl_next;

    list_for_each_entry(svc, &dp_vs_svc_match_list, m_list) {
        rte_rwlock_write_lock(&svc->acl_lock);
        list_for_each_entry_safe(acl_curr, acl_next, &svc->acl_list, list) {
            list_del(&acl_curr->list);
            rte_free(acl_curr);
        }
        rte_rwlock_write_unlock(&svc->acl_lock);
    }

    return EDPVS_OK;
}

int dp_vs_acl(struct dp_vs_acl_flow *acl_flow, struct dp_vs_service *svc)
{
    if (!acl_flow || !svc) {
        return EDPVS_INVAL;
    }
    struct dp_vs_acl *acl = NULL;

    rte_rwlock_read_lock(&svc->acl_lock);
    acl = dp_vs_acl_lookup(acl_flow->af, &acl_flow->saddr,
                                 &acl_flow->daddr, acl_flow->sport,
                                 acl_flow->dport, svc);
    if (acl == NULL) {
        rte_rwlock_read_unlock(&svc->acl_lock);
        return EDPVS_OK;
    }

    /* if current connections exceeds maximum amount that confirmed */
    if (acl->p_conn >= acl->max_conn) {
        ++acl->d_conn;
        rte_rwlock_read_unlock(&svc->acl_lock);
        return EDPVS_DROP;
    }

    /* permit for all, except for black names */
    if (svc->acl_all & IP_VS_ACL_PERMIT_ALL) {
        if (acl->rule == IP_VS_ACL_DENY) {
            ++acl->d_conn;
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_DROP;
        }
        ++acl->p_conn;
        rte_rwlock_read_unlock(&svc->acl_lock);
        return EDPVS_ACCEPT;
    }

    /* deny for all, except for white names */
    if (!(svc->acl_all | IP_VS_ACL_DENY_ALL)) {
        if (acl->rule == IP_VS_ACL_PERMIT) {
            ++acl->p_conn;
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_ACCEPT;
        }
        ++acl->d_conn;
        rte_rwlock_read_unlock(&svc->acl_lock);
        return EDPVS_DROP;
    }

    rte_rwlock_read_unlock(&svc->acl_lock);
    return EDPVS_ACCEPT;
}

static int dp_vs_acl_getall(struct dp_vs_service *svc,
                            struct dp_vs_acl_entry **acls, size_t *num_acls)
{
    if (!svc || !acls || !num_acls) {
        return EDPVS_INVAL;
    }

    struct dp_vs_acl *acl;
    struct dp_vs_acl_entry *acl_entry;
    int i;

    rte_rwlock_read_lock(&svc->acl_lock);
    if (svc->num_acls > 0) {
        *num_acls = svc->num_acls;
        *acls = rte_malloc_socket(0, sizeof(struct dp_vs_acl_entry) * svc->num_acls,
                    RTE_CACHE_LINE_SIZE, rte_socket_id());
        if (!(*acls)) {
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_NOMEM;
        }

        i = 0;
        acl_entry = *acls;
        list_for_each_entry(acl, &svc->acl_list, list) {
            assert(i < *num_acls);
            acl_entry[i].af = acl->af;
            acl_entry[i].proto = svc->proto;
            inet_addr_range_dump(svc->af, &acl->srange, acl_entry[i].srange,
                        sizeof(acl_entry[i].srange));
            inet_addr_range_dump(svc->af, &acl->drange, acl_entry[i].drange,
                        sizeof(acl_entry[i].drange));
            acl_entry[i].rule = acl->rule;
            acl_entry[i].max_conn = acl->max_conn;
            acl_entry[i].p_conn = acl->p_conn;
            acl_entry[i].d_conn = acl->d_conn;
            ++i;
        }
    } else {
        *num_acls = 0;
        *acls = NULL;
    }

    rte_rwlock_read_unlock(&svc->acl_lock);
    return EDPVS_OK;
}

/*
 * for control plane
 */
static int acl_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct dp_vs_acl_conf *acl_conf = conf;
    struct dp_vs_service *svc;
    struct dp_vs_match match;
    int err;

    if (opt == SOCKOPT_SET_ACL_FLUSH) {
        return dp_vs_acl_flushall();
    }

    if (!conf || size < sizeof(*acl_conf)) {
        return EDPVS_INVAL;
    }

    if (dp_vs_match_parse(acl_conf->m_srange, acl_conf->m_drange,
                          acl_conf->iifname, acl_conf->oifname,
                          &match) != EDPVS_OK) {
        return EDPVS_INVAL;
    }

    svc = dp_vs_service_lookup(acl_conf->af, acl_conf->proto,
                               &acl_conf->vaddr, acl_conf->vport,
                               acl_conf->fwmark, NULL, &match);
    if (!svc) {
        return EDPVS_NOSERV;
    }

    switch (opt) {
        case SOCKOPT_SET_ACL_ADD:
            err = dp_vs_acl_add(acl_conf->af,
                                acl_conf->srange, acl_conf->drange,
                                acl_conf->rule, acl_conf->max_conn,
                                svc);
            break;
        case SOCKOPT_SET_ACL_DEL:
            err = dp_vs_acl_del(acl_conf->af,
                                acl_conf->srange, acl_conf->drange,
                                acl_conf->rule, acl_conf->max_conn,
                                svc);
            break;
        default:
            err = EDPVS_NOTSUPP;
            break;
    }

    dp_vs_service_put(svc);

    return err;
}

static int acl_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                           void **out, size_t *outsize)
{
    const struct dp_vs_acl_conf *acl_conf = conf;
    struct dp_vs_get_acls *get;
    struct dp_vs_acl_entry *acls;

    struct dp_vs_service *svc;
    size_t num_acls;
    int err, i;
    struct dp_vs_match match;

    if (!conf || size < sizeof(*acl_conf)) {
        return EDPVS_INVAL;
    }

    if (dp_vs_match_parse(acl_conf->m_srange, acl_conf->m_drange,
                          acl_conf->iifname, acl_conf->oifname,
                          &match) != EDPVS_OK) {
        return EDPVS_INVAL;
    }

    svc = dp_vs_service_lookup(acl_conf->af, acl_conf->proto,
                               &acl_conf->vaddr, acl_conf->vport,
                               acl_conf->fwmark, NULL, &match);
    if (!svc) {
        return EDPVS_NOSERV;
    }

    switch (opt) {
        case SOCKOPT_GET_ACL_ALL:
            err = dp_vs_acl_getall(svc, &acls, &num_acls);
            if (err != EDPVS_OK) {
                break;
            }

            *outsize = sizeof(*get) + num_acls * sizeof(struct dp_vs_acl_entry);
            *out = rte_malloc_socket(0, *outsize, RTE_CACHE_LINE_SIZE, rte_socket_id());
            if (!*out) {
                if (acls) {
                    rte_free(acls);
                }
                err = EDPVS_NOMEM;
                break;
            }

            get = *out;
            get->num_acls = num_acls;

            for (i = 0; i < num_acls; ++i) {
                get->entrytable[i].af = acls[i].af;
                get->entrytable[i].proto = acls[i].proto;
                snprintf(get->entrytable[i].srange,
                         sizeof(acls[i].srange), "%s", acls[i].srange);
                snprintf(get->entrytable[i].drange,
                         sizeof(acls[i].drange), "%s", acls[i].drange);
                get->entrytable[i].rule = acls[i].rule;
                get->entrytable[i].max_conn = acls[i].max_conn;
                get->entrytable[i].p_conn = acls[i].p_conn;
                get->entrytable[i].d_conn = acls[i].d_conn;
            }

            if (acls) {
                rte_free(acls);
            }
            break;
        default:
            err = EDPVS_NOTSUPP;
            break;
    }

    dp_vs_service_put(svc);
    return err;
}

struct dpvs_sockopts acl_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_ACL_ADD,
    .set_opt_max    = SOCKOPT_SET_ACL_FLUSH,
    .set            = acl_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_ACL_ALL,
    .get_opt_max    = SOCKOPT_GET_ACL_ALL,
    .get            = acl_sockopt_get,
};

int dp_vs_acl_init(void)
{
    int err;
    if ((err = sockopt_register(&acl_sockopts)) != EDPVS_OK) {
        return err;
    }

    return EDPVS_OK;
}

int dp_vs_acl_term(void)
{
    int err;

    if ((err = sockopt_unregister(&acl_sockopts)) != EDPVS_OK) {
        return err;
    }
    return EDPVS_OK;
}
