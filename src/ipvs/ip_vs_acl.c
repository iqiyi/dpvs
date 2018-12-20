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
#include "linux_ipv6.h"
#include "ipvs/ipvs.h"

#define DPVS_ACL_TAB_BITS    16
#define DPVS_ACL_TAB_SIZE    (1 << DPVS_ACL_TAB_BITS)
#define DPVS_ACL_TAB_MASK    (DPVS_ACL_TAB_SIZE - 1)

static uint32_t dp_vs_acl_rnd; /* hash random */

static struct dp_vs_acl *dp_vs_acl_find(struct dp_vs_acl *acl,
                                        struct list_head *head,
                                        enum DP_VS_ACL_FIND_TYPE type);

#if 0
static inline bool __flow_in_range(int af,
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
#endif

static inline bool
judge_port_betw(__be16 port, __be16 min_port, __be16 max_port)
{
    if (unlikely(ntohs(min_port) > ntohs(max_port)))
        return false;

    if (max_port != 0) {
        if (ntohs(port) < ntohs(min_port) ||
            ntohs(port) > ntohs(max_port)) {
            return false;
        }
    }
    return true;
}

/*
 * addr & port was network bytes order
 */
static inline uint32_t
dp_vs_acl_hashkey(int af, union inet_addr *addr)
{
    if (!addr)
        return 0;

    uint32_t hashkey;

    if (AF_INET == af) {
        hashkey = rte_jhash(&addr->in, sizeof(addr->in), dp_vs_acl_rnd)
            & DPVS_ACL_TAB_MASK;
    } else {
        hashkey = rte_jhash(&addr->in6, sizeof(addr->in6), dp_vs_acl_rnd)
            & DPVS_ACL_TAB_MASK;
    }

    return hashkey;
}

static int
__acl_parse_add(const char *range, int rule, int max_conn,
                struct dp_vs_service *svc, enum DPVS_ACL_EDGE edge)
{
    if (!range || !strlen(range) || !svc)
        return EDPVS_INVAL;

    struct dp_vs_acl *new_acl, *acl;
    struct inet_addr_range addr_range;
    union inet_addr min_addr, max_addr;
    __be16 min_port, max_port;
    int af, err;
    uint32_t ip_cnt = 0, i, hashkey;

    memset(&addr_range, 0, sizeof(addr_range));
    err = inet_addr_range_parse(range, &addr_range, &af);
    if (err != EDPVS_OK)
        return err;

    memmove(&min_addr, &addr_range.min_addr, sizeof(union inet_addr));
    memmove(&max_addr, &addr_range.max_addr, sizeof(union inet_addr));
    min_port = addr_range.min_port;
    max_port = addr_range.max_port;

    if (AF_INET == af) {
        union inet_addr curr_addr;
        memset(&curr_addr, 0, sizeof(curr_addr));

        ip_cnt = ntohl(max_addr.in.s_addr) - ntohl(min_addr.in.s_addr);
        for (i = 0; i <= ip_cnt; ++i) {
            curr_addr.in.s_addr = htonl(ntohl(min_addr.in.s_addr) + i);
            hashkey = dp_vs_acl_hashkey(af, &curr_addr);

            new_acl = rte_zmalloc("dp_vs_acl", sizeof(*new_acl), 0);
            if (!new_acl) {
                return EDPVS_NOMEM;
            }

            new_acl->rule           = rule;
            new_acl->af             = af;
            memmove(&new_acl->addr, &curr_addr, sizeof(union inet_addr));
            new_acl->min_port       = min_port;
            new_acl->max_port       = max_port;
            new_acl->max_conn       = max_conn;

            rte_rwlock_write_lock(&svc->acl_lock);
            acl = dp_vs_acl_find(new_acl, &aclhash_src(svc)[hashkey], DP_VS_ACL_ADD);
            if (acl != NULL) {
#ifdef CONFIG_DPVS_ACL_DEBUG
                RTE_LOG(DEBUG, ACL, "%s: address with acl already exist.\n", __func__);
#endif
                rte_rwlock_write_unlock(&svc->acl_lock);
                rte_free(new_acl);
                return EDPVS_EXIST;
            }
            list_add_tail(&new_acl->list, &svc->acl_list[edge][hashkey]);
            rte_rwlock_write_unlock(&svc->acl_lock);
        }
    } else {
        /* fix me, support ipv6 later */
    }

    return EDPVS_OK;
}

static int
dp_vs_acl_add(const char *srange, const char *drange,
              int rule, int max_conn, struct dp_vs_service *svc)
{
    if (!svc || !srange || !drange)
        return EDPVS_INVAL;

    int err = EDPVS_OK;
    err = __acl_parse_add(srange, rule, max_conn, svc, DPVS_ACL_EDGE_SRC);
    if (err != EDPVS_OK)
        return EDPVS_INVAL;

    err = __acl_parse_add(drange, rule, max_conn, svc, DPVS_ACL_EDGE_DST);
    if (err != EDPVS_OK)
        return EDPVS_INVAL;

    return EDPVS_OK;
}

static struct dp_vs_acl *
dp_vs_acl_find(struct dp_vs_acl *acl, struct list_head *head,
               enum DP_VS_ACL_FIND_TYPE type)
{
    struct dp_vs_acl *acl_iter;

    switch (type) {
        case DP_VS_ACL_ADD:
            list_for_each_entry(acl_iter, head, list) {
                if (acl_iter->af == acl->af &&
                    inet_addr_equal(acl->af, &acl_iter->addr, &acl->addr)) {
                    return acl_iter;
                }
            }
            break;

        case DP_VS_ACL_DEL:
            list_for_each_entry(acl_iter, head, list) {
                if (acl_iter->rule == acl->rule &&
                    acl_iter->af   == acl->af   &&
                    inet_addr_equal(acl->af, &acl_iter->addr, &acl->addr) &&
                    acl_iter->min_port == acl->min_port &&
                    acl_iter->max_port == acl->max_port &&
                    acl_iter->max_conn == acl->max_conn) {
                    return acl_iter;
                }
            }
            break;
    }

    return NULL;
}

static struct dp_vs_acl *
dp_vs_acl_lookup(int af, union inet_addr *addr, __be16 port,
                 struct list_head *hash_table, uint32_t hashkey)
{
    if (!addr || !hash_table)
        return NULL;

    struct list_head *head = &hash_table[hashkey];
    struct dp_vs_acl *acl;

    list_for_each_entry(acl, head, list) {
#ifdef CONFIG_DPVS_ACL_DEBUG
        char buf[64], sbuf[64];
        RTE_LOG(DEBUG, ACL, "acl lookup: %s:%u <- %s:%u -> %s:%u\n",
                inet_ntop(af, &acl->addr, buf, sizeof(buf)) ? buf : "::",
                ntohs(acl->min_port),
                inet_ntop(af, addr, sbuf, sizeof(sbuf)) ? sbuf : "::",
                ntohs(port),
                buf, ntohs(acl->max_port));
#endif
        if (acl->af == af &&
            inet_addr_equal(af, &acl->addr, addr) &&
            judge_port_betw(port, acl->min_port, acl->max_port)) {
            return acl;
        }
    }

    return NULL;
}

static int
__acl_parse_del(const char *range, int rule, int max_conn,
                struct dp_vs_service *svc, enum DPVS_ACL_EDGE edge)
{
    if (!range || !strlen(range) || !svc)
        return EDPVS_INVAL;

    struct dp_vs_acl *new_acl, *acl;
    struct inet_addr_range addr_range;
    union inet_addr min_addr, max_addr;
    __be16 min_port, max_port;
    int af, err;
    uint32_t ip_cnt = 0, i, hashkey;

    memset(&addr_range, 0, sizeof(addr_range));
    err = inet_addr_range_parse(range, &addr_range, &af);
    if (err != EDPVS_OK)
        return err;

    memmove(&min_addr, &addr_range.min_addr, sizeof(union inet_addr));
    memmove(&max_addr, &addr_range.max_addr, sizeof(union inet_addr));
    min_port = addr_range.min_port;
    max_port = addr_range.max_port;

    if (AF_INET == af) {
        union inet_addr curr_addr;
        memset(&curr_addr, 0, sizeof(curr_addr));

        ip_cnt = ntohl(max_addr.in.s_addr) - ntohl(min_addr.in.s_addr);
        for (i = 0; i <= ip_cnt; ++i) {
            curr_addr.in.s_addr = htonl(ntohl(min_addr.in.s_addr) + i);
            hashkey = dp_vs_acl_hashkey(af, &curr_addr);

            new_acl = rte_zmalloc("dp_vs_acl", sizeof(*new_acl), 0);
            if (!new_acl) {
                return EDPVS_NOMEM;
            }

            new_acl->rule           = rule;
            new_acl->af             = af;
            memmove(&new_acl->addr, &curr_addr, sizeof(union inet_addr));
            new_acl->min_port       = min_port;
            new_acl->max_port       = max_port;
            new_acl->max_conn       = max_conn;

            rte_rwlock_write_lock(&svc->acl_lock);
            acl = dp_vs_acl_find(new_acl, &aclhash_src(svc)[hashkey], DP_VS_ACL_DEL);
            if (acl == NULL) {
#ifdef CONFIG_DPVS_ACL_DEBUG
                RTE_LOG(DEBUG, ACL, "%s: not find acl to del.\n", __func__);
#endif
                rte_rwlock_write_unlock(&svc->acl_lock);
                rte_free(new_acl);
                return EDPVS_NOTEXIST;
            }
#ifdef CONFIG_DPVS_ACL_DEBUG
            RTE_LOG(DEBUG, ACL, "%s: find acl to del.\n", __func__);
#endif
            list_del(&acl->list);
            rte_free(acl);
            rte_free(new_acl);
            rte_rwlock_write_unlock(&svc->acl_lock);
        }
    } else {
        /* fix me, support ipv6 later */
    }

    return EDPVS_OK;
}

static int
dp_vs_acl_del(const char *srange, const char *drange,
              int rule, int max_conn, struct dp_vs_service *svc)
{
    if (!svc || !srange || !drange)
        return EDPVS_INVAL;

    int err = EDPVS_OK;
    err = __acl_parse_del(srange, rule, max_conn, svc, DPVS_ACL_EDGE_SRC);
    if (err != EDPVS_OK)
        return EDPVS_INVAL;

    err = __acl_parse_del(drange, rule, max_conn, svc, DPVS_ACL_EDGE_DST);
    if (err != EDPVS_OK)
        return EDPVS_INVAL;

    return EDPVS_OK;
}

int dp_vs_acl_flush(struct dp_vs_service *svc)
{
    if (!svc)
        return EDPVS_INVAL;

    if (svc->acl_hashed == DP_VS_MATCH_ACL_NOTHASHED)
        return EDPVS_OK;

    struct dp_vs_acl *acl_curr, *acl_next;
    int i;

    rte_rwlock_write_lock(&svc->acl_lock);
    for (i = 0; i < DPVS_ACL_TAB_SIZE; ++i) {
        list_for_each_entry_safe(acl_curr, acl_next, &aclhash_src(svc)[i], list) {
            list_del(&acl_curr->list);
            rte_free(acl_curr);
        }

        list_for_each_entry_safe(acl_curr, acl_next, &aclhash_dst(svc)[i], list) {
            list_del(&acl_curr->list);
            rte_free(acl_curr);
        }
    }

    rte_rwlock_write_unlock(&svc->acl_lock);

    return EDPVS_OK;
}

static int
__acl_judge(struct dp_vs_service *svc, struct dp_vs_acl *acl)
{
    if (!acl)
        return EDPVS_INVAL;

    rte_rwlock_read_lock(&svc->acl_lock);

    /* permit for all, except for black names */
    if (svc->rule_all & IP_VS_ACL_PERMIT_ALL) {
        if (acl->rule == IP_VS_ACL_DENY) {
            ++acl->d_conn;
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_DROP;
        }
        /* max_conn only take effect when not 0 */
        if (acl->max_conn && acl->p_conn >= acl->max_conn) {
            ++acl->d_conn;
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_DROP;
        }
        ++acl->p_conn;
        rte_rwlock_read_unlock(&svc->acl_lock);
        return EDPVS_OK;
    }

    /* deny for all, except for white names */
    if (!(svc->rule_all | IP_VS_ACL_DENY_ALL)) {
        if (acl->rule == IP_VS_ACL_PERMIT) {
            if (acl->max_conn && acl->p_conn >= acl->max_conn) {
                ++acl->d_conn;
                rte_rwlock_read_unlock(&svc->acl_lock);
                return EDPVS_DROP;
            }
            ++acl->p_conn;
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_OK;
        }
        ++acl->d_conn;
        rte_rwlock_read_unlock(&svc->acl_lock);
        return EDPVS_DROP;
    }

    rte_rwlock_read_unlock(&svc->acl_lock);
    return EDPVS_OK;
}

int dp_vs_acl_judge(struct dp_vs_acl_flow *flow, struct dp_vs_service *svc)
{
    if (!flow || !svc)
        return EDPVS_INVAL;

    struct dp_vs_acl *acl = NULL;
    uint32_t hashkey;

    /* judge for src & port */
    hashkey = dp_vs_acl_hashkey(flow->af, &flow->saddr);

    rte_rwlock_read_lock(&svc->acl_lock);
    acl = dp_vs_acl_lookup(flow->af, &flow->saddr, flow->sport,
                           aclhash_src(svc), hashkey);
    if (acl) {
        if (__acl_judge(svc, acl) != EDPVS_OK) {
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_DROP;
        }
    }

    hashkey = dp_vs_acl_hashkey(flow->af, &flow->daddr);
    acl = dp_vs_acl_lookup(flow->af, &flow->daddr, flow->dport,
                           aclhash_dst(svc), hashkey);
    if (acl) {
        if (__acl_judge(svc, acl) != EDPVS_OK) {
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_DROP;
        }
    }

    rte_rwlock_read_unlock(&svc->acl_lock);
    return EDPVS_OK;
}

#if 0
static int dp_vs_acl_getall(struct dp_vs_service *svc,
                            struct dp_vs_acl_entry **acls, size_t *num_acls)
{
    if (!svc || !acls || !num_acls)
        return EDPVS_INVAL;

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
#endif

static void acl_init_hash_table(struct dp_vs_service *svc)
{
    if (svc->acl_hashed & DP_VS_MATCH_ACL_HASHED)
        return;

    int i;
    aclhash_src(svc) = rte_malloc_socket(NULL,
                sizeof(struct list_head) * DPVS_ACL_TAB_SIZE,
                RTE_CACHE_LINE_SIZE, rte_socket_id());
    aclhash_dst(svc) = rte_malloc_socket(NULL,
                sizeof(struct list_head) * DPVS_ACL_TAB_SIZE,
                RTE_CACHE_LINE_SIZE, rte_socket_id());

    for (i = 0; i < DPVS_ACL_TAB_SIZE; ++i) {
        INIT_LIST_HEAD(&aclhash_src(svc)[i]);
        INIT_LIST_HEAD(&aclhash_dst(svc)[i]);
    }

    svc->acl_hashed |= DP_VS_MATCH_ACL_HASHED;
}

static int
acl_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct dp_vs_acl_conf *acl_conf = conf;
    struct dp_vs_service *svc;
    struct dp_vs_match match;
    int err;

    if (!conf || size < sizeof(*acl_conf)) {
        return EDPVS_INVAL;
    }

    if (dp_vs_match_parse(acl_conf->m_srange, acl_conf->m_drange,
                          acl_conf->iifname, acl_conf->oifname,
                          &match) != EDPVS_OK) {
        return EDPVS_INVAL;
    }

    svc = dp_vs_service_lookup(match.af, acl_conf->proto,
                               &acl_conf->vaddr, acl_conf->vport,
                               acl_conf->fwmark, NULL, &match);
    if (!svc) {
        return EDPVS_NOSERV;
    }

    /* found match & svc, then init acl src and dst hash table */
    acl_init_hash_table(svc);

    switch (opt) {
        case SOCKOPT_SET_ACL_ADD:
            err = dp_vs_acl_add(acl_conf->srange, acl_conf->drange,
                                acl_conf->rule, acl_conf->max_conn,
                                svc);
            break;

        case SOCKOPT_SET_ACL_DEL:
            err = dp_vs_acl_del(acl_conf->srange, acl_conf->drange,
                                acl_conf->rule, acl_conf->max_conn,
                                svc);
            break;

        case SOCKOPT_SET_ACL_FLUSH:
            err = dp_vs_acl_flush(svc);
            break;

        default:
            err = EDPVS_NOTSUPP;
            break;
    }

    dp_vs_service_put(svc);
    return err;
}

static int
acl_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                void **out, size_t *outsize)
{
    return EDPVS_OK;

#if 0
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
#endif
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

    dp_vs_acl_rnd = (uint32_t)random();

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
