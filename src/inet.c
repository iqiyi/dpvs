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
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include "inet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "route.h"
#include "route6.h"
#include "neigh.h"
#include "icmp.h"
#include "icmp6.h"
#include "inetaddr.h"
#include "lldp.h"

#define INET
#define RTE_LOGTYPE_INET RTE_LOGTYPE_USER1

static struct list_head inet_hooks[INET_HOOK_NUMHOOKS];
static rte_rwlock_t inet_hook_lock;

static struct list_head inet6_hooks[INET_HOOK_NUMHOOKS];
static rte_rwlock_t inet6_hook_lock;

static inline struct list_head *af_inet_hooks(int af, size_t num)
{
    assert((af == AF_INET || af == AF_INET6) && num < INET_HOOK_NUMHOOKS);

    if (af == AF_INET)
        return &inet_hooks[num];
    else
        return &inet6_hooks[num];
}

static inline rte_rwlock_t *af_inet_hook_lock(int af)
{
    assert(af == AF_INET || af == AF_INET6);

    if (af == AF_INET)
        return &inet_hook_lock;
    else
        return &inet6_hook_lock;
}

static int inet_hook_init(void)
{
    int i;

    rte_rwlock_init(&inet_hook_lock);
    rte_rwlock_write_lock(&inet_hook_lock);
    for (i = 0; i < NELEMS(inet_hooks); i++)
        INIT_LIST_HEAD(&inet_hooks[i]);
    rte_rwlock_write_unlock(&inet_hook_lock);

    rte_rwlock_init(&inet6_hook_lock);
    rte_rwlock_write_lock(&inet6_hook_lock);
    for (i = 0; i < NELEMS(inet6_hooks); i++)
            INIT_LIST_HEAD(&inet6_hooks[i]);
    rte_rwlock_write_unlock(&inet6_hook_lock);

    return EDPVS_OK;
}

int inet_init(void)
{
    int err;

    if ((err = neigh_init()) != 0)
        return err;
    if ((err = route_init()) != 0)
        return err;
    if ((err = route6_init()) != 0)
        return err;
    if ((err = inet_hook_init()) != 0)
        return err;
    if ((err = ipv4_init()) != 0)
        return err;
    if ((err = ipv6_init()) != 0)
        return err;
    if ((err = icmp_init()) != 0)
        return err;
    if ((err = icmpv6_init()) != 0)
        return err;
    if ((err = inet_addr_init()) != 0)
        return err;
    if ((err = dpvs_lldp_init()) != 0)
        return err;

    return EDPVS_OK;
}

int inet_term(void)
{
    int err;

    if ((err = dpvs_lldp_term()) != 0)
        return err;
    if ((err = inet_addr_term()) != 0)
        return err;
    if ((err = icmpv6_term()) != 0)
        return err;
    if ((err = icmp_term()) != 0)
        return err;
    if ((err = ipv6_term()) != 0)
        return err;
    if ((err = ipv4_term()) != 0)
        return err;
    if ((err = route6_term()) != 0)
        return err;
    if ((err = route_term()) != 0)
        return err;
    if ((err = neigh_term()) != 0)
        return err;

    return EDPVS_OK;
}

bool inet_addr_equal(int af, const union inet_addr *a1,
                     const union inet_addr *a2)
{
    switch (af) {
    case AF_INET:
        return a1->in.s_addr == a2->in.s_addr;
    case AF_INET6:
        return memcmp(a1->in6.s6_addr, a2->in6.s6_addr, 16) == 0;
    default:
        return memcmp(a1, a2, sizeof(union inet_addr)) == 0;
    }
}

bool inet_is_addr_any(int af, const union inet_addr *addr)
{
    switch (af) {
    case AF_INET:
        return addr->in.s_addr == htonl(INADDR_ANY);
    case AF_INET6:
        return IN6_ARE_ADDR_EQUAL(&addr->in6, &in6addr_any);
    default:
        return false; /* ? */
    }
}

int inet_plen_to_mask(int af, uint8_t plen, union inet_addr *mask)
{
    switch (af) {
    case AF_INET:
        if (plen == 0)
            return mask->in.s_addr = 0;
        return mask->in.s_addr = htonl(~((1U<<(32-plen))-1));
    case AF_INET6:
        return EDPVS_NOTSUPP;
    default:
        return EDPVS_INVAL;
    }
}

int inet_addr_net(int af, const union inet_addr *addr,
                  const union inet_addr *mask,
                  union inet_addr *net)
{
    switch (af) {
    case AF_INET:
        net->in.s_addr = addr->in.s_addr & mask->in.s_addr;
        break;
    case AF_INET6:
        return EDPVS_NOTSUPP;
    default:
        return EDPVS_INVAL;
    }

    return EDPVS_OK;
}

bool inet_addr_same_net(int af, uint8_t plen,
                        const union inet_addr *addr1,
                        const union inet_addr *addr2)
{
    uint32_t mask;

    switch (af) {
    case AF_INET:
        mask = htonl(~((0x1<<(32-plen)) - 1));
        return !((addr1->in.s_addr^addr2->in.s_addr)&mask);
    case AF_INET6:
        return ipv6_prefix_equal(&addr1->in6, &addr2->in6, plen);
    default:
        return false;
    }
}

static int __inet_register_hooks(struct list_head *head,
                                 struct inet_hook_ops *reg)
{
    struct inet_hook_ops *elem;

    /* check if exist */
    list_for_each_entry(elem, head, list) {
        if (elem == reg) {
            RTE_LOG(ERR, INET, "%s: hook already exist\n", __func__);
            return EDPVS_EXIST; /* error ? */
        }
    }

    list_for_each_entry(elem, head, list) {
        if (reg->priority < elem->priority)
            break;
    }
    list_add(&reg->list, elem->list.prev);

    return EDPVS_OK;
}

int INET_HOOK(int af, unsigned int hook, struct rte_mbuf *mbuf,
              struct netif_port *in, struct netif_port *out,
              int (*okfn)(struct rte_mbuf *mbuf))
{
    struct list_head *hook_list;
    struct inet_hook_ops *ops;
    struct inet_hook_state state;
    int verdict = INET_ACCEPT;

    state.hook = hook;
    hook_list = af_inet_hooks(af, hook);

    ops = list_entry(hook_list, struct inet_hook_ops, list);

    if (!list_empty(hook_list)) {
        verdict = INET_ACCEPT;
        list_for_each_entry_continue(ops, hook_list, list) {
repeat:
            verdict = ops->hook(ops->priv, mbuf, &state);
            if (verdict != INET_ACCEPT) {
                if (verdict == INET_REPEAT)
                    goto repeat;
                break;
            }
        }
    }

    if (verdict == INET_ACCEPT || verdict == INET_STOP) {
        return okfn(mbuf);
    } else if (verdict == INET_DROP) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_DROP;
    } else { /* INET_STOLEN */
        return EDPVS_OK;
    }
}

int inet_register_hooks(struct inet_hook_ops *reg, size_t n)
{
    int af;
    size_t i, err;
    struct list_head *hook_list;
    assert(reg);

    for (i = 0; i < n; i++) {
        af = reg[i].af;
        if (reg[i].hooknum >= INET_HOOK_NUMHOOKS || !reg[i].hook) {
            err = EDPVS_INVAL;
            goto rollback;
        }
        hook_list = af_inet_hooks(af, reg[i].hooknum);

        rte_rwlock_write_lock(af_inet_hook_lock(af));
        err = __inet_register_hooks(hook_list, &reg[i]);
        rte_rwlock_write_unlock(af_inet_hook_lock(af));

        if (err != EDPVS_OK)
            goto rollback;
    }

    return EDPVS_OK;

rollback:
    inet_unregister_hooks(reg, n);
    return err;
}

int inet_unregister_hooks(struct inet_hook_ops *reg, size_t n)
{
    int af;
    size_t i;
    struct inet_hook_ops *elem, *next;
    struct list_head *hook_list;
    assert(reg);

    for (i = 0; i < n; i++) {
        af = reg[i].af;
        if (reg[i].hooknum >= INET_HOOK_NUMHOOKS) {
            RTE_LOG(WARNING, INET, "%s: bad hook number\n", __func__);
            continue; /* return error ? */
        }
        hook_list = af_inet_hooks(af, reg[i].hooknum);

#ifdef CONFIG_DPVS_IPV4_INET_HOOK
        rte_rwlock_write_lock(&inet_hook_lock);
#endif
        list_for_each_entry_safe(elem, next, hook_list, list) {
            if (elem == &reg[i]) {
                list_del(&elem->list);
                break;
            }
        }
#ifdef CONFIG_DPVS_IPV4_INET_HOOK
        rte_rwlock_write_unlock(&inet_hook_lock);
#endif
        if (&elem->list == hook_list)
            RTE_LOG(WARNING, INET, "%s: hook not found\n", __func__);
    }

    return EDPVS_OK;
}

void inet_stats_add(struct inet_stats *stats, const struct inet_stats *diff)
{
   stats->inpkts            += diff->inpkts;
   stats->inoctets          += diff->inoctets;
   stats->indelivers        += diff->indelivers;
   stats->outforwdatagrams  += diff->outforwdatagrams;
   stats->outpkts           += diff->outpkts;
   stats->outoctets         += diff->outoctets;
   stats->inhdrerrors       += diff->inhdrerrors;
   stats->intoobigerrors    += diff->intoobigerrors;
   stats->innoroutes        += diff->innoroutes;
   stats->inaddrerrors      += diff->inaddrerrors;
   stats->inunknownprotos   += diff->inunknownprotos;
   stats->intruncatedpkts   += diff->intruncatedpkts;
   stats->indiscards        += diff->indiscards;
   stats->outdiscards       += diff->outdiscards;
   stats->outnoroutes       += diff->outnoroutes;
   stats->reasmtimeout      += diff->reasmtimeout;
   stats->reasmreqds        += diff->reasmreqds;
   stats->reasmoks          += diff->reasmoks;
   stats->reasmfails        += diff->reasmfails;
   stats->fragoks           += diff->fragoks;
   stats->fragfails         += diff->fragfails;
   stats->fragcreates       += diff->fragcreates;
   stats->inmcastpkts       += diff->inmcastpkts;
   stats->outmcastpkts      += diff->outmcastpkts;
   stats->inbcastpkts       += diff->inbcastpkts;
   stats->outbcastpkts      += diff->outbcastpkts;
   stats->inmcastoctets     += diff->inmcastoctets;
   stats->outmcastoctets    += diff->outmcastoctets;
   stats->inbcastoctets     += diff->inbcastoctets;
   stats->outbcastoctets    += diff->outbcastoctets;
   stats->csumerrors        += diff->csumerrors;
   stats->noectpkts         += diff->noectpkts;
   stats->ect1pkts          += diff->ect1pkts;
   stats->ect0pkts          += diff->ect0pkts;
   stats->cepkts            += diff->cepkts;
}
