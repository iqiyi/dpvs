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

#define DPVS_ACL_TAB_BITS    18
#define DPVS_ACL_TAB_SIZE    (1 << DPVS_ACL_TAB_BITS)
#define DPVS_ACL_TAB_MASK    (DPVS_ACL_TAB_SIZE - 1)

static uint32_t dp_vs_acl_rnd; /* hash random */

static struct dp_vs_acl *
dp_vs_acl_find(struct dp_vs_acl *acl, struct dp_vs_service *svc,
               uint32_t hashkey, enum DP_VS_ACL_FIND_TYPE type);

static inline char* get_acl_rule_name(int rule)
{
    switch (rule) {
        case IP_VS_ACL_PERMIT:
            return "permit";
            break;

        case IP_VS_ACL_DENY:
            return "deny";
            break;

        default:
            return "unknown";
    }
}

inline void print_acl_verdict_result(int verdict)
{
    if (verdict == EDPVS_DROP) {
        RTE_LOG(DEBUG, ACL, "%s: connection denied by acl.\n", __func__);
    } else  {
        RTE_LOG(DEBUG, ACL, "%s: connection permitted by acl.\n", __func__);
    }
}

static inline bool
judge_addr_matched(int af, union inet_addr *addr1, union inet_addr *addr2)
{
    /* if addr2 is zero, means need not check. */
    if (!inet_is_addr_any(af, addr2)) {
        return inet_addr_equal(af, addr1, addr1);
    }
    return true;
}

static inline bool
judge_port_betw(__be16 port, __be16 min_port, __be16 max_port)
{
    if (unlikely(ntohs(min_port) > ntohs(max_port)))
        return false;

    /* if both min/max are zero, means need not check. */
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
dp_vs_acl_hashkey(int src_af, union inet_addr *saddr,
                  int dst_af, union inet_addr *daddr)
{
    if (!saddr || !daddr)
        return 0;

    uint32_t hashkey;
    uint32_t saddr_fold, daddr_fold;

    saddr_fold = inet_addr_fold(src_af, saddr);
    daddr_fold = inet_addr_fold(dst_af, daddr);

    if (!saddr_fold && !daddr_fold) {
        RTE_LOG(DEBUG, ACL, "%s: IP proto not support in acl.\n", __func__);
        return 0;
    }

    /* jhash hurts performance, we do not use rte_jhash_2words here */
    hashkey = ((rte_be_to_cpu_32(saddr_fold) * 31 +
                    rte_be_to_cpu_32(daddr_fold)) * 31 + dp_vs_acl_rnd) &
        DPVS_ACL_TAB_MASK;

    return hashkey;
}

/*
 * ipv4 support: 192.168.0.1-192.168.0.254
 * ipv6 support: 2001::1-2001::FFFF, only the last 16 bit range
 */
static int
__calc_addr_cnt(int af, union inet_addr *min_addr, union inet_addr *max_addr)
{
    if (!min_addr || !max_addr)
        return 0;

    int addr_cnt = 0;

    if (AF_INET == af) {
        addr_cnt = ntohl(max_addr->in.s_addr) - ntohl(min_addr->in.s_addr) + 1;
    } else {
        addr_cnt = ntohs(max_addr->in6.s6_addr16[0]) -
                                         ntohs(min_addr->in6.s6_addr16[0]) + 1;
    }

    return (addr_cnt >= 0) ? addr_cnt : 0;
}

static void
__make_curr_addr(int af, union inet_addr *addr, int inc, union inet_addr *ret)
{
    if (!addr)
        return;

    memmove(ret, addr, sizeof(union inet_addr));

    if (AF_INET == af) {
        ret->in.s_addr = htonl(ntohl(addr->in.s_addr) + inc);
    } else {
        ret->in6.s6_addr16[0] = htons(ntohs(addr->in6.s6_addr16[0]) + inc);
    }
}

static int
__acl_parse_add(const char *srange, const char *drange,
                int rule, int max_conn, struct dp_vs_service *svc)
{
    if (!svc)
        return EDPVS_INVAL;

    if ((!srange || !strlen(srange)) && (!drange || !strlen(drange)))
        return EDPVS_INVAL;

    struct dp_vs_acl *new_acl, *acl;
    struct inet_addr_range saddr_range, daddr_range;
    union inet_addr curr_saddr, curr_daddr;
    int src_af = AF_INET, dst_af = AF_INET, err;    /* in case of Nat64 */
    uint32_t i, j, hashkey;
    uint32_t saddr_cnt, daddr_cnt;
    uint32_t fail_cnt = 0, success_cnt = 0;

    memset(&saddr_range, 0, sizeof(saddr_range));
    memset(&daddr_range, 0, sizeof(daddr_range));

    err = inet_addr_range_parse(srange, &saddr_range, &src_af);
    if (err != EDPVS_OK)
        return err;

    err = inet_addr_range_parse(drange, &daddr_range, &dst_af);
    if (err != EDPVS_OK)
        return err;

    saddr_cnt = __calc_addr_cnt(src_af, &saddr_range.min_addr,
                                        &saddr_range.max_addr);
    daddr_cnt = __calc_addr_cnt(dst_af, &daddr_range.min_addr,
                                        &daddr_range.max_addr);

    rte_rwlock_write_lock(&svc->acl_lock);
    for (i = 0; i < saddr_cnt; ++i) {
        for (j = 0; j < daddr_cnt; ++j) {
            memset(&curr_saddr, 0, sizeof(curr_saddr));
            memset(&curr_daddr, 0, sizeof(curr_daddr));
            __make_curr_addr(src_af, &saddr_range.min_addr, i, &curr_saddr);
            __make_curr_addr(dst_af, &daddr_range.min_addr, j, &curr_daddr);

            hashkey = dp_vs_acl_hashkey(src_af, &curr_saddr,
                                        dst_af, &curr_daddr);

            new_acl = rte_zmalloc("dp_vs_acl", sizeof(*new_acl), 0);
            if (!new_acl) {
                return EDPVS_NOMEM;
            }

            new_acl->rule           = rule;
            new_acl->max_conn       = max_conn;
            new_acl->saddr.af       = src_af;
            memmove(&new_acl->saddr.addr, &curr_saddr, sizeof(union inet_addr));
            new_acl->saddr.min_port = saddr_range.min_port;
            new_acl->saddr.max_port = saddr_range.max_port;
            new_acl->daddr.af       = dst_af;
            memmove(&new_acl->daddr.addr, &curr_daddr, sizeof(union inet_addr));
            new_acl->daddr.min_port = daddr_range.min_port;
            new_acl->daddr.max_port = daddr_range.max_port;

            acl = dp_vs_acl_find(new_acl, svc, hashkey, DP_VS_ACL_ADD);
            if (acl != NULL) {
                ++fail_cnt;
                rte_free(new_acl);
                continue;
            }
            ++success_cnt;
            list_add_tail(&new_acl->list, &svc->acl_list[hashkey]);
        }
    }

    svc->num_acls += success_cnt;
    rte_rwlock_write_unlock(&svc->acl_lock);

#ifdef CONFIG_DPVS_ACL_DEBUG
    RTE_LOG(DEBUG, ACL, "%s: %u acls has been successfully added, %u already in.\n",
                __func__, success_cnt, fail_cnt);
#endif

    return EDPVS_OK;
}

static int
dp_vs_acl_add(const char *srange, const char *drange,
              int rule, int max_conn, struct dp_vs_service *svc)
{
    if (!svc || !srange || !drange)
        return EDPVS_INVAL;

    int err = EDPVS_OK;

    err = __acl_parse_add(srange, drange, rule, max_conn, svc);
    if (err != EDPVS_OK)
        return EDPVS_INVAL;

    return err;
}

static inline bool
__acl_add_judge_equal(struct dp_vs_acl *acl1, struct dp_vs_acl *acl2)
{
    if (!acl1 || !acl2)
        return false;

    return acl1->saddr.af == acl2->saddr.af &&
           inet_addr_equal(acl1->saddr.af, &acl1->saddr.addr,
                                        &acl2->saddr.addr) &&
           acl1->daddr.af == acl2->daddr.af &&
           inet_addr_equal(acl1->daddr.af, &acl1->daddr.addr,
                                        &acl2->daddr.addr);
}

static inline bool
__acl_del_judge_equal(struct dp_vs_acl *acl1, struct dp_vs_acl *acl2)
{
    if (!acl1 || !acl2)
        return false;
    return acl1->rule == acl2->rule &&
           acl1->max_conn == acl2->max_conn &&
           !memcmp(&acl1->saddr, &acl2->saddr, sizeof(acl1->saddr)) &&
           !memcmp(&acl1->daddr, &acl2->daddr, sizeof(acl1->daddr));

}

static struct dp_vs_acl *
dp_vs_acl_find(struct dp_vs_acl *acl, struct dp_vs_service *svc,
               uint32_t hashkey, enum DP_VS_ACL_FIND_TYPE type)
{
    if (!acl || !svc || !(svc->acl_hashed | DP_VS_MATCH_ACL_NOTHASHED))
        return NULL;

    struct dp_vs_acl *acl_iter;
    struct list_head *head = &svc->acl_list[hashkey];

    switch (type) {
        case DP_VS_ACL_ADD:
            list_for_each_entry(acl_iter, head, list) {
                if (__acl_add_judge_equal(acl_iter, acl)) {
                    return acl_iter;
                }
            }
            break;

        case DP_VS_ACL_DEL:
            list_for_each_entry(acl_iter, head, list) {
                if (__acl_del_judge_equal(acl_iter, acl)) {
                    return acl_iter;
                }
            }
            break;
    }

    return NULL;
}

static struct dp_vs_acl *
dp_vs_acl_lookup(struct dp_vs_acl_flow *flow,
                 struct dp_vs_service *svc, uint32_t hashkey)
{
    if (!flow || !svc || !(svc->acl_hashed | DP_VS_MATCH_ACL_NOTHASHED))
        return NULL;

    struct list_head *head = &svc->acl_list[hashkey];
    struct dp_vs_acl *acl;

    list_for_each_entry(acl, head, list) {
#ifdef CONFIG_DPVS_ACL_DEBUG
        char sbuf[64], dbuf[64];
        RTE_LOG(DEBUG, ACL, "flow info : %s:%u -> %s:%u %s\n",
                inet_ntop(flow->saddr.af,
                    &flow->saddr.addr, sbuf, sizeof(sbuf)) ? sbuf : "::",
                ntohs(flow->sport),
                inet_ntop(flow->daddr.af,
                    &flow->daddr.addr, dbuf, sizeof(dbuf)) ? dbuf : "::",
                ntohs(flow->dport), inet_proto_name(svc->proto));
        RTE_LOG(DEBUG, ACL, "acl lookup: %s:%u-%u -> %s:%u-%u rule = %s\n",
                inet_ntop(acl->saddr.af,
                    &acl->saddr.addr, sbuf, sizeof(sbuf)) ? sbuf : "::",
                ntohs(acl->saddr.min_port), ntohs(acl->saddr.max_port),
                inet_ntop(acl->daddr.af,
                    &acl->daddr.addr, dbuf, sizeof(dbuf)) ? dbuf : "::",
                ntohs(acl->daddr.min_port), ntohs(acl->daddr.max_port),
                get_acl_rule_name(acl->rule));
#endif
        if (acl->saddr.af == flow->saddr.af &&
            judge_addr_matched(acl->saddr.af, &flow->saddr.addr,
                &acl->saddr.addr) &&
            judge_port_betw(flow->sport, acl->saddr.min_port,
                acl->saddr.max_port) &&
            acl->daddr.af == flow->daddr.af &&
            judge_addr_matched(acl->daddr.af, &flow->daddr.addr,
                &acl->daddr.addr) &&
            judge_port_betw(flow->dport, acl->daddr.min_port,
                            acl->daddr.max_port)) {
            return acl;
        }
    }

    return NULL;
}

static int
__acl_parse_del(const char *srange, const char *drange,
                int rule, int max_conn, struct dp_vs_service *svc)
{
    if (!svc)
        return EDPVS_INVAL;

    if ((!srange || !strlen(srange)) && (!drange || !strlen(drange)))
        return EDPVS_INVAL;


    struct dp_vs_acl new_acl, *acl;
    struct inet_addr_range saddr_range, daddr_range;
    union inet_addr curr_saddr, curr_daddr;
    int src_af = AF_INET, dst_af = AF_INET, err;    /* in case of Nat64 */
    uint32_t i, j, hashkey;
    uint32_t saddr_cnt, daddr_cnt;
    uint32_t fail_cnt = 0, success_cnt = 0;

    memset(&saddr_range, 0, sizeof(saddr_range));
    memset(&daddr_range, 0, sizeof(daddr_range));

    err = inet_addr_range_parse(srange, &saddr_range, &src_af);
    if (err != EDPVS_OK)
        return err;

    err = inet_addr_range_parse(drange, &daddr_range, &dst_af);
    if (err != EDPVS_OK)
        return err;

    saddr_cnt = __calc_addr_cnt(src_af, &saddr_range.min_addr,
                                        &saddr_range.max_addr);
    daddr_cnt = __calc_addr_cnt(dst_af, &daddr_range.min_addr,
                                        &daddr_range.max_addr);

    rte_rwlock_write_lock(&svc->acl_lock);
    for (i = 0; i < saddr_cnt; ++i) {
        for (j = 0; j < daddr_cnt; ++j) {
            memset(&curr_saddr, 0, sizeof(curr_saddr));
            memset(&curr_daddr, 0, sizeof(curr_daddr));
            __make_curr_addr(src_af, &saddr_range.min_addr, i, &curr_saddr);
            __make_curr_addr(dst_af, &daddr_range.min_addr, j, &curr_daddr);

            hashkey = dp_vs_acl_hashkey(src_af, &curr_saddr,
                                        dst_af, &curr_daddr);

            memset(&new_acl, 0, sizeof(new_acl));
            new_acl.rule           = rule;
            new_acl.max_conn       = max_conn;
            new_acl.saddr.af       = src_af;
            memmove(&new_acl.saddr.addr, &curr_saddr, sizeof(union inet_addr));
            new_acl.saddr.min_port = saddr_range.min_port;
            new_acl.saddr.max_port = saddr_range.max_port;
            new_acl.daddr.af       = dst_af;
            memmove(&new_acl.daddr.addr, &curr_daddr, sizeof(union inet_addr));
            new_acl.daddr.min_port = daddr_range.min_port;
            new_acl.daddr.max_port = daddr_range.max_port;

            acl = dp_vs_acl_find(&new_acl, svc, hashkey, DP_VS_ACL_DEL);

            if (acl == NULL) {
                ++fail_cnt;
                continue;
            }
            list_del(&acl->list);
            rte_free(acl);
            ++success_cnt;
        }
    }

    if (svc->num_acls < success_cnt) {
        RTE_LOG(ERR, ACL, "%s: svc->num_acls = %u < %u to delete.\n",
                    __func__, svc->num_acls, success_cnt);
    }
    svc->num_acls -= success_cnt;
    rte_rwlock_write_unlock(&svc->acl_lock);

#ifdef CONFIG_DPVS_ACL_DEBUG
    RTE_LOG(DEBUG, ACL, "%s: %u acls has been successfully deleted, %u not found.\n",
                __func__, success_cnt, fail_cnt);
#endif

    return EDPVS_OK;
}

static int
dp_vs_acl_del(const char *srange, const char *drange,
              int rule, int max_conn, struct dp_vs_service *svc)
{
    if (!svc || !srange || !drange)
        return EDPVS_INVAL;

    int err = EDPVS_OK;
    err = __acl_parse_del(srange, drange, rule, max_conn, svc);
    if (err != EDPVS_OK)
        return EDPVS_INVAL;

    return EDPVS_OK;
}

int dp_vs_acl_flush(struct dp_vs_service *svc)
{
    if (!svc)
        return EDPVS_INVAL;

    if (!(svc->acl_hashed | DP_VS_MATCH_ACL_NOTHASHED))
        return EDPVS_OK;

    struct dp_vs_acl *acl_curr, *acl_next;
    int i;

    rte_rwlock_write_lock(&svc->acl_lock);
    for (i = 0; i < DPVS_ACL_TAB_SIZE; ++i) {
        list_for_each_entry_safe(acl_curr, acl_next, &svc->acl_list[i], list) {
            list_del(&acl_curr->list);
            rte_free(acl_curr);
            --svc->num_acls;
        }
    }

    rte_rwlock_write_unlock(&svc->acl_lock);

    return EDPVS_OK;
}

static int
__acl_verdict(struct dp_vs_service *svc, struct dp_vs_acl *acl)
{
    if (!acl || !svc)
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

int dp_vs_acl_verdict(struct dp_vs_acl_flow *flow, struct dp_vs_service *svc)
{
    if (!flow || !svc)
        return EDPVS_INVAL;

    struct dp_vs_acl *acl = NULL;
    uint32_t hashkey;
    union inet_addr zero_addr;

    hashkey = dp_vs_acl_hashkey(flow->saddr.af, &flow->saddr.addr,
                flow->daddr.af, &flow->daddr.addr);

    rte_rwlock_read_lock(&svc->acl_lock);
    acl = dp_vs_acl_lookup(flow, svc, hashkey);
    if (acl) {
        if (__acl_verdict(svc, acl) != EDPVS_OK) {
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_DROP;
        } else {
            goto out;
        }
    }

    /* if hashed dst addr was zero */
    memset(&zero_addr, 0, sizeof(zero_addr));
    hashkey = dp_vs_acl_hashkey(flow->saddr.af, &flow->saddr.addr,
                flow->daddr.af, &zero_addr);
    acl = dp_vs_acl_lookup(flow, svc, hashkey);
    if (acl) {
        if (__acl_verdict(svc, acl) != EDPVS_OK) {
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_DROP;
        } else {
            goto out;
        }
    }

    /* if hashed source addr was zero */
    memset(&zero_addr, 0, sizeof(zero_addr));
    hashkey = dp_vs_acl_hashkey(flow->saddr.af, &zero_addr,
                flow->daddr.af, &flow->daddr.addr);
    acl = dp_vs_acl_lookup(flow, svc, hashkey);
    if (acl) {
        if (__acl_verdict(svc, acl) != EDPVS_OK) {
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_DROP;
        } else  {
            goto out;
        }
    }

    /* if rule of match was defalt 'deny' */
    if (svc->rule_all == IP_VS_ACL_DENY_ALL) {
        rte_rwlock_read_unlock(&svc->acl_lock);
        return EDPVS_DROP;
    }

out:
    rte_rwlock_read_unlock(&svc->acl_lock);
    return EDPVS_OK;
}

static int dp_vs_acl_getall(struct dp_vs_service *svc,
                            struct dp_vs_acl_entry **acls, size_t *num_acls)
{
    if (!svc || !acls || !num_acls)
        return EDPVS_INVAL;

    if (!(svc->acl_hashed | DP_VS_MATCH_ACL_NOTHASHED)) {
        *num_acls = 0;
        *acls = NULL;
        return EDPVS_OK;
    }

    struct dp_vs_acl *acl;
    struct dp_vs_acl_entry *acl_entry;
    int i = 0, index = 0;

    rte_rwlock_read_lock(&svc->acl_lock);
    if (svc->num_acls > 0) {
        *num_acls = svc->num_acls;
        *acls = rte_malloc_socket(NULL,
                    sizeof(struct dp_vs_acl_entry) * svc->num_acls,
                    RTE_CACHE_LINE_SIZE, rte_socket_id());
        if (!(*acls)) {
            rte_rwlock_read_unlock(&svc->acl_lock);
            return EDPVS_NOMEM;
        }

        i = 0;
        index = 0;
        acl_entry = *acls;

        for (i = 0; i < DPVS_ACL_TAB_SIZE; ++i) {
            list_for_each_entry(acl, &svc->acl_list[i], list) {
                assert(index < *num_acls);

                acl_entry[index].rule     = acl->rule;
                acl_entry[index].max_conn = acl->max_conn;
                acl_entry[index].p_conn   = acl->p_conn;
                acl_entry[index].d_conn   = acl->d_conn;
                memmove(&acl_entry[index].saddr,
                            &acl->saddr, sizeof(acl->saddr));
                memmove(&acl_entry[index].daddr,
                            &acl->daddr, sizeof(acl->daddr));

                ++index;
            }
        }
    } else {
        *num_acls = 0;
        *acls = NULL;
    }

    rte_rwlock_read_unlock(&svc->acl_lock);
    return EDPVS_OK;
}

static void acl_init_hash_table(struct dp_vs_service *svc)
{
    if (svc->acl_hashed & DP_VS_MATCH_ACL_HASHED)
        return;

    int i;
    svc->acl_list = rte_malloc_socket(NULL,
                sizeof(struct list_head) * DPVS_ACL_TAB_SIZE,
                RTE_CACHE_LINE_SIZE, rte_socket_id());

    for (i = 0; i < DPVS_ACL_TAB_SIZE; ++i) {
        INIT_LIST_HEAD(&svc->acl_list[i]);
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
                               NULL, 0, 0, NULL, &match);
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
                               NULL, 0, 0, NULL, &match);
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
            *out = rte_malloc_socket(NULL, *outsize,
                        RTE_CACHE_LINE_SIZE, rte_socket_id());
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
                get->entrytable[i].rule = acls[i].rule;
                get->entrytable[i].max_conn = acls[i].max_conn;
                get->entrytable[i].p_conn = acls[i].p_conn;
                get->entrytable[i].d_conn = acls[i].d_conn;
                memmove(&get->entrytable[i].saddr,
                            &acls[i].saddr, sizeof(struct dp_vs_acl_addr));
                memmove(&get->entrytable[i].daddr,
                            &acls[i].daddr, sizeof(struct dp_vs_acl_addr));
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
