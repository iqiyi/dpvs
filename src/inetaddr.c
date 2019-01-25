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
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <linux/if_addr.h>
#include "common.h"
#include "dpdk.h"
#include "netif.h"
#include "timer.h"
#include "route.h"
#include "ctrl.h"
#include "sa_pool.h"
#include "inetaddr.h"
#include "neigh.h"
#include "netif_addr.h"
#include "conf/inetaddr.h"
#include "route6.h"
#include "ndisc.h"

#define IFA
#define RTE_LOGTYPE_IFA             RTE_LOGTYPE_USER1
#define INET_ADDR_LOCK

#define INET_ADDR_HSIZE_SHIFT       8
#define INET_ADDR_HSIZE             (1U << INET_ADDR_HSIZE_SHIFT)

enum ifaddr_timer_t
{
    INET_NONE,
    INET_DAD
};

static struct list_head     in_addr_tab[INET_ADDR_HSIZE];
static rte_rwlock_t         in_addr_lock;
static rte_atomic32_t       in_addr_cnt;

static inline struct inet_device *dev_get_idev(const struct netif_port *dev)
{
    assert(dev && dev->in_ptr);
    rte_atomic32_inc(&dev->in_ptr->refcnt);
    return dev->in_ptr;
}

static void idev_put(struct inet_device *idev)
{
    rte_atomic32_dec(&idev->refcnt);
}

static uint32_t inline in_addr_hash(struct in_addr *in)
{
    uint32_t hash;

    hash = (in->s_addr * 0x61C88647) >> (32 - INET_ADDR_HSIZE_SHIFT);
    return hash % INET_ADDR_HSIZE;
}

static inline bool ifa_prefix_check(int af, const union inet_addr *addr,
                                    uint8_t plen)
{
    if ((af != AF_INET && af != AF_INET6)
            || inet_is_addr_any(af, addr)
            || (af == AF_INET && plen > 32)
            || (af == AF_INET6 && plen > 128))
        return false;
    else
        return true;
}

/* zero for infinity lifetime */
static void ifa_set_lifetime(struct inet_ifaddr *ifa,
                             uint32_t valid_lft, uint32_t prefered_lft)
{
    /* XXX: do not support prefered_lft */
    prefered_lft = valid_lft;

    if (!valid_lft)
        ifa->flags |= IFA_F_PERMANENT;
    else
        ifa->flags &= ~IFA_F_PERMANENT;

    ifa->valid_lft = valid_lft;
    ifa->prefered_lft = prefered_lft;
    return;
}

static struct inet_ifaddr *__ifa_lookup(struct inet_device *idev,
                                        const union inet_addr *addr,
                                        uint8_t plen, int af)
{
    struct inet_ifaddr *ifa;

    list_for_each_entry(ifa, &idev->ifa_list, d_list) {
        if ((!plen || ifa->plen == plen) && ifa->af == af
             && inet_addr_equal(ifa->af, &ifa->addr, addr)) {
            return ifa;
        }
    }

    return NULL;
}

static int __ifa_insert(struct inet_device *idev, struct inet_ifaddr *ifa)
{
    uint32_t hash = in_addr_hash(&ifa->addr.in);

    /* add to inet_device's list */
    list_add(&ifa->d_list, &idev->ifa_list);
    rte_atomic32_inc(&ifa->refcnt);

    /* add to global hash table */
    list_add(&ifa->h_list, &in_addr_tab[hash]);
    rte_atomic32_inc(&ifa->refcnt);

    return EDPVS_OK;
}

static inline void ___ifa_remove(struct inet_ifaddr *ifa)
{
    list_del(&ifa->d_list);
    list_del(&ifa->h_list);
    INIT_LIST_HEAD(&ifa->d_list);
    INIT_LIST_HEAD(&ifa->h_list);
}

/* make lookup and remove atmomic, also cancel the timer */
static int __ifa_remove(struct inet_device *idev, const union inet_addr *addr,
                        uint8_t plen, struct inet_ifaddr **ifa, int af)
{
    struct inet_ifaddr *ent;

    if ((ent = __ifa_lookup(idev, addr, plen, af)) == NULL)
        return EDPVS_NOTEXIST;

    if (rte_atomic32_read(&ent->refcnt) > 2)
        return EDPVS_BUSY;

    ___ifa_remove(ent);

    if (ifa)
        *ifa = ent;
    return EDPVS_OK;
}

static int __ifa_add_route4(struct inet_ifaddr *ifa)
{
    int err;
    union inet_addr net;

    err = route_add(&ifa->addr.in, 32, RTF_LOCALIN,
                    NULL, ifa->idev->dev, NULL, 0, 0);
    /* may already added by same IP with diff plen */
    if (err != EDPVS_OK && err != EDPVS_EXIST)
        return err;

    if (ifa->plen == 32)
        return EDPVS_OK;

    err = inet_addr_net(ifa->af, &ifa->addr, &ifa->mask, &net);
    if (err != EDPVS_OK)
        goto errout;

    err = route_add(&net.in, ifa->plen, RTF_FORWARD,
                    NULL, ifa->idev->dev, &ifa->addr.in, 0, 0);
    /* may already added by another IP */
    if (err != EDPVS_OK && err != EDPVS_EXIST)
        goto errout;

    return EDPVS_OK;

errout:
    route_del(&ifa->addr.in, ifa->plen, RTF_LOCALIN,
              NULL, ifa->idev->dev, NULL, 0, 0);
    return err;
}

static int __ifa_add_route6(struct inet_ifaddr *ifa)
{
    int err;
    struct in6_addr net;

    err = route6_add(&ifa->addr.in6, 128, RTF_LOCALIN,
                     &in6addr_any, ifa->idev->dev,
                     &in6addr_any, ifa->idev->dev->mtu);

    if (err != EDPVS_OK && err != EDPVS_EXIST)
        return err;

    if (ifa->plen == 128)
        return EDPVS_OK;

    ipv6_addr_prefix(&net, &ifa->addr.in6, ifa->plen);

    err = route6_add(&net, ifa->plen, RTF_FORWARD,
                     &in6addr_any, ifa->idev->dev,
                     &in6addr_any, ifa->idev->dev->mtu);

    if (err != EDPVS_OK && err != EDPVS_EXIST)
        goto errout;

    return EDPVS_OK;

errout:
    route6_del(&ifa->addr.in6, 128, RTF_LOCALIN,
               &in6addr_any, ifa->idev->dev,
               &in6addr_any, ifa->idev->dev->mtu);
    return err;
}

static int ifa_add_route(struct inet_ifaddr *ifa)
{
    if (ifa->af == AF_INET)
        return __ifa_add_route4(ifa);
    else if(ifa->af == AF_INET6)
        return __ifa_add_route6(ifa);
    else
        return EDPVS_NOTSUPP;
}

static int __ifa_del_route4(struct inet_ifaddr *ifa)
{
    int err;
    union inet_addr net;

    err = route_del(&ifa->addr.in, 32, RTF_LOCALIN,
                    NULL, ifa->idev->dev, NULL, 0, 0);
    if (err != EDPVS_OK && err != EDPVS_NOTEXIST)
        RTE_LOG(WARNING, IFA, "%s: fail to delete route", __func__);

    if (ifa->plen == 32)
        return EDPVS_OK;

    err = inet_addr_net(ifa->af, &ifa->addr, &ifa->mask, &net);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IFA, "%s: fail to delete route", __func__);

    err = route_del(&net.in, ifa->plen, RTF_FORWARD,
                    NULL, ifa->idev->dev, &ifa->addr.in, 0, 0);
    if (err != EDPVS_OK && err != EDPVS_NOTEXIST)
        RTE_LOG(WARNING, IFA, "%s: fail to delete route", __func__);

    return EDPVS_OK;
}

static int __ifa_del_route6(struct inet_ifaddr *ifa)
{
    int err;
    struct in6_addr net;

    err = route6_del(&ifa->addr.in6, 128, RTF_LOCALIN,
                     &in6addr_any, ifa->idev->dev,
                     &in6addr_any, ifa->idev->dev->mtu);
    if (err != EDPVS_OK && err != EDPVS_NOTEXIST)
        RTE_LOG(WARNING, IFA, "%s: fail to delete route", __func__);

    if (ifa->plen == 128)
        return EDPVS_OK;

    ipv6_addr_prefix(&net, &ifa->addr.in6, ifa->plen);

    err = route6_del(&net, ifa->plen, RTF_FORWARD,
                     &in6addr_any, ifa->idev->dev,
                     &in6addr_any, ifa->idev->dev->mtu);
    if (err != EDPVS_OK && err != EDPVS_NOTEXIST)
        RTE_LOG(WARNING, IFA, "%s: fail to delete route", __func__);

    return EDPVS_OK;
}

static int ifa_del_route(struct inet_ifaddr *ifa)
{
    if (ifa->af == AF_INET)
        return __ifa_del_route4(ifa);
    else if(ifa->af == AF_INET6)
        return __ifa_del_route6(ifa);
    else
        return EDPVS_NOTSUPP;
}

static struct inet_ifmcaddr *__imc_lookup( int af, const struct inet_device *idev,
                                           const union inet_addr *maddr)
{
    struct inet_ifmcaddr *imc;

    list_for_each_entry(imc, &idev->ifm_list, d_list) {
        if (inet_addr_equal(af, &imc->addr, maddr)) {
            return imc;
        }
    }

    return NULL;
}

static int idev_mc_add(int af, struct inet_device *idev,
                       const union inet_addr *maddr)
{
    struct inet_ifmcaddr  *imc;

    imc = __imc_lookup(af, idev, maddr);
    if (imc) {
        rte_atomic32_inc(&imc->refcnt);
        return EDPVS_OK;
    }

    imc = rte_calloc(NULL, 1, sizeof(struct inet_ifmcaddr), RTE_CACHE_LINE_SIZE);
    if (!imc) {
        return EDPVS_NOMEM;
    }

    imc->idev = idev;
    memcpy(&imc->addr, maddr, sizeof(*maddr));
    list_add(&imc->d_list, &idev->ifm_list);
    rte_atomic32_set(&imc->refcnt, 1);

    return EDPVS_OK;
}

static int idev_mc_del(int af, struct inet_device *idev,
                      const union inet_addr *maddr)
{
    struct inet_ifmcaddr *imc;

    imc = __imc_lookup(af, idev, maddr);
    if (!imc) {
        return EDPVS_NOTEXIST;
    }

    rte_atomic32_dec(&imc->refcnt);
    if (rte_atomic32_read(&imc->refcnt) < 1) {
        list_del(&imc->d_list);
        rte_free(imc);
    }
    return EDPVS_OK;
}

/* support ipv6 only, and not support source filter */
static int ifa_add_del_mcast(struct inet_ifaddr *ifa, bool add)
{
    union inet_addr iaddr;
    struct ether_addr eaddr;
    int err = 0;

    if (ifa->af != AF_INET6)
        return EDPVS_OK;

    memset(&iaddr, 0, sizeof(iaddr));
    memset(&eaddr, 0, sizeof(eaddr));

    addrconf_addr_solict_mult(&ifa->addr.in6, &iaddr.in6);
    ipv6_mac_mult(&iaddr.in6, &eaddr);

    if (add) {
        err = idev_mc_add(ifa->af, ifa->idev, &iaddr);
        if (err)
            return err;

        err = netif_mc_add(ifa->idev->dev, &eaddr);
        if (err) {
            /* rollback */
            idev_mc_del(ifa->af, ifa->idev, &iaddr);
            return err;
        }
    } else {
        err = idev_mc_del(ifa->af, ifa->idev, &iaddr);
        if (err)
            return err;

        err = netif_mc_del(ifa->idev->dev, &eaddr);
        if (err) {
            /* rollback */
            idev_mc_add(ifa->af, ifa->idev, &iaddr);
            return err;
        }
    }

    return err;
}

static int inet_ifaddr_dad_completed(void *arg)
{
    struct inet_ifaddr *ifa = arg;

    rte_rwlock_write_lock(&in_addr_lock);
    ifa->flags &= ~(IFA_F_TENTATIVE|IFA_F_OPTIMISTIC|IFA_F_DADFAILED);
    rte_rwlock_write_unlock(&in_addr_lock);

    return DTIMER_STOP;
}

/* change timer callback, refer to 'addrconf_mod_timer' */
static void inet_ifaddr_mod_timer(struct inet_ifaddr *ifa,
                                  enum ifaddr_timer_t what,
                                  struct timeval *when)
{
    dpvs_timer_cancel(&ifa->timer, true);

    switch (what) {
    case INET_DAD:
        dpvs_timer_sched(&ifa->timer, when, inet_ifaddr_dad_completed,
                                                           ifa, true);
        break;
    /* TODO: other timer support */
    default:
        break;
    }
}

static void inet_ifaddr_dad_stop(struct inet_ifaddr *ifa, int dad_failed)
{
    rte_rwlock_write_lock(&in_addr_lock);
    if (ifa->flags & IFA_F_PERMANENT) {
        if (dad_failed && ifa->flags & IFA_F_TENTATIVE)
            ifa->flags |= IFA_F_DADFAILED;
        dpvs_timer_cancel(&ifa->timer, true);
        rte_rwlock_write_unlock(&in_addr_lock);
    } else if (ifa->flags & IFA_F_TEMPORARY) {
        /* TODO: support privacy addr */
        RTE_LOG(ERR, IFA, "%s: Not support privacy addr\n", __func__);
        rte_rwlock_write_unlock(&in_addr_lock);
    } else {
        inet_addr_del(AF_INET6, ifa->idev->dev, &ifa->addr, ifa->plen);
        rte_rwlock_write_unlock(&in_addr_lock);
    }
}

/* recv DAD: change ifa's state */
void inet_ifaddr_dad_failure(struct inet_ifaddr *ifa)
{
    inet_ifaddr_dad_stop(ifa, 1);
}

/* call me by lock */
static void inet_ifaddr_dad_start(struct inet_ifaddr *ifa)
{
    struct timeval tv;

    if (ifa->flags & IFA_F_NODAD ||
        !(ifa->flags & IFA_F_TENTATIVE)) {
        ifa->flags &= ~(IFA_F_TENTATIVE|IFA_F_OPTIMISTIC|IFA_F_DADFAILED);
        return;
    }

    tv.tv_sec  = 3;
    tv.tv_usec = 0;

    ifa->flags |= IFA_F_TENTATIVE | IFA_F_OPTIMISTIC;
    inet_ifaddr_mod_timer(ifa, INET_DAD, &tv);
    ndisc_send_dad(ifa->idev->dev, &ifa->addr.in6);
}

/*
 * no need to rollback, dpvs can not start successfully;
 * should not be init in 'inetaddr_init';
 * because multicast address should be added after port_start
 */
int idev_add_mcast_init(struct netif_port *dev)
{
    struct inet_device *idev;
    struct ether_addr eaddr_nodes, eaddr_routers;
    union inet_addr all_nodes, all_routers;
    int err = 0;

    idev = dev_get_idev(dev);

    memset(&eaddr_nodes, 0, sizeof(eaddr_nodes));
    memset(&eaddr_routers, 0, sizeof(eaddr_routers));

    memcpy(&all_nodes, &in6addr_linklocal_allnodes, sizeof(all_nodes));
    memcpy(&all_routers, &in6addr_linklocal_allrouters, sizeof(all_routers));

    ipv6_mac_mult(&all_nodes.in6, &eaddr_nodes);
    ipv6_mac_mult(&all_routers.in6, &eaddr_routers);

    rte_rwlock_write_lock(&in_addr_lock);
    err = idev_mc_add(AF_INET6, idev, &all_nodes);
    if (err != EDPVS_OK)
        goto errout;
    err = netif_mc_add(idev->dev, &eaddr_nodes);
    if (err != EDPVS_OK)
        goto free_idev_nodes;
    err = idev_mc_add(AF_INET6, idev, &all_routers);
    if (err != EDPVS_OK)
        goto free_netif_nodes;
    err = netif_mc_add(idev->dev, &eaddr_routers);
    if (err != EDPVS_OK)
        goto free_idev_routers;

    rte_rwlock_write_unlock(&in_addr_lock);
    idev_put(idev);

    return EDPVS_OK;

free_idev_routers:
    idev_mc_del(AF_INET6, idev, &all_routers);
free_netif_nodes:
    netif_mc_del(idev->dev, &eaddr_nodes);
free_idev_nodes:
    idev_mc_del(AF_INET6, idev, &all_nodes);
errout:
    rte_rwlock_write_unlock(&in_addr_lock);
    idev_put(idev);
    return err;
}

static int ifa_expire(void *arg)
{
    struct inet_ifaddr *ifa = arg;
    struct timeval tv;

    /**
     * TODO: handle invalid/prefered lifttime
     * move to expire list instead of delete ?
     */
    rte_rwlock_write_lock(&in_addr_lock);
    if (rte_atomic32_read(&ifa->refcnt) > 2) {
        RTE_LOG(WARNING, IFA, "%s: addr in use, try expire later\n", __func__);
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        dpvs_timer_update(&ifa->timer, &tv, true);
        rte_rwlock_write_unlock(&in_addr_lock);
        return DTIMER_OK;
    }

    list_del(&ifa->d_list);
    list_del(&ifa->h_list);
    INIT_LIST_HEAD(&ifa->d_list);
    INIT_LIST_HEAD(&ifa->h_list);

    dpvs_timer_cancel(&ifa->timer, true);
    if (ifa->flags & IFA_F_SAPOOL)
        sa_pool_destroy(ifa);
    ifa_add_del_mcast(ifa, false);
    ifa_del_route(ifa);
    idev_put(ifa->idev);
    rte_atomic32_dec(&ifa->idev->ifa_cnt);
    rte_free(ifa);
    rte_atomic32_dec(&in_addr_cnt);

    rte_rwlock_write_unlock(&in_addr_lock);
    return DTIMER_STOP;
}

static int ifa_add_set(int af, const struct netif_port *dev,
                       const union inet_addr *addr, uint8_t plen,
                       const union inet_addr *bcast,
                       uint32_t valid_lft, uint32_t prefered_lft,
                       uint8_t scope, uint32_t flags, bool create)
{
    struct inet_device *idev = NULL;
    struct inet_ifaddr *ifa = NULL;
    struct timeval timeo = {0};
    int err;
    char addr_str[64];

    if (!dev || !ifa_prefix_check(af, addr, plen))
        return EDPVS_INVAL;

    idev = dev_get_idev(dev);
    if (!idev)
        return EDPVS_RESOURCE;

    inet_ntop(af, &addr->in.s_addr, addr_str, sizeof(addr_str));
    RTE_LOG(INFO, IFA, "try to add %s in %s \n", addr_str, __func__);

    rte_rwlock_write_lock(&in_addr_lock);

    ifa = __ifa_lookup(idev, addr, plen, af);
    if (ifa && create) {
        err = EDPVS_EXIST;
        goto errout;
    } else if (!ifa && !create) {
        err = EDPVS_NOTEXIST;
        goto errout;
    }

    if (!ifa) {
        ifa = rte_calloc(NULL, 1, sizeof(*ifa), RTE_CACHE_LINE_SIZE);
        if (!ifa) {
            err = EDPVS_NOMEM;
            goto errout;
        }

        ifa->af   = af;
        ifa->idev = idev;
        ifa->addr = *addr;
        ifa->plen = plen;
        ifa->flags = flags;

        if (af == AF_INET)
            inet_plen_to_mask(af, plen, &ifa->mask);

        dpvs_time_now(&ifa->cstemp, true);
        rte_atomic32_init(&ifa->refcnt);

        /* set mult*/
        err = ifa_add_del_mcast(ifa, true);
        if (err != EDPVS_OK)
            goto free_ifa;

        /* set routes for local and network */
        err = ifa_add_route(ifa);
        if (err != EDPVS_OK && err != EDPVS_EXIST)
            goto del_mc;

        err = __ifa_insert(idev, ifa);
        if (err != EDPVS_OK)
            goto del_route;

        if (ifa->flags & IFA_F_SAPOOL) {
            err = sa_pool_create(ifa, 0, 0);
            if (err != EDPVS_OK)
                goto rem_ifa;
        }

        /* add counter for idev and gobal */
        rte_atomic32_inc(&idev->ifa_cnt);
        rte_atomic32_inc(&in_addr_cnt);
        /* hold idev */
        rte_atomic32_inc(&idev->refcnt);
    }

    if (bcast)
        ifa->bcast = *bcast;
    if (scope)
        ifa->scope = scope;
    ifa_set_lifetime(ifa, valid_lft, prefered_lft);
    dpvs_time_now(&ifa->tstemp, true); /* mod time */

    /* timer */
    if (create) {
        if (!(ifa->flags & IFA_F_PERMANENT)) {
            timeo.tv_sec = ifa->valid_lft;
            dpvs_timer_sched(&ifa->timer, &timeo, ifa_expire, ifa, true);
        }
    } else {
        /* ok to cancel a timer not scheduled */
        dpvs_timer_cancel(&ifa->timer, true);

        if (!(ifa->flags & IFA_F_PERMANENT)) {
            timeo.tv_sec = ifa->valid_lft;
            dpvs_timer_sched(&ifa->timer, &timeo, ifa_expire, ifa, true);
        }
    }

    /* TODO: support privacy addr, don't need it now */
    if (af == AF_INET6) {
        assert(ifa->flags & IFA_F_PERMANENT);
    }

    if ((af == AF_INET6) && (ifa->flags & IFA_F_PERMANENT)) {
        ifa->flags |= IFA_F_TENTATIVE|IFA_F_OPTIMISTIC;
        inet_ifaddr_dad_start(ifa);
    }

    rte_rwlock_write_unlock(&in_addr_lock);
    idev_put(idev);
    return EDPVS_OK;

rem_ifa:
    ___ifa_remove(ifa);
del_route:
    ifa_del_route(ifa);
del_mc:
    ifa_add_del_mcast(ifa, false);
free_ifa:
    rte_free(ifa);
errout:
    rte_rwlock_write_unlock(&in_addr_lock);
    idev_put(idev);
    RTE_LOG(WARNING, IFA, "add %s in %s failed\n", addr_str, __func__);
    return err;
}

int inet_addr_add(int af, const struct netif_port *dev,
                  const union inet_addr *addr, uint8_t plen,
                  const union inet_addr *bcast,
                  uint32_t valid_lft, uint32_t prefered_lft,
                  uint8_t scope, uint32_t flags)
{
    return ifa_add_set(af, dev, addr, plen, bcast, valid_lft, prefered_lft,
                       scope, flags, true);
}

int inet_addr_mod(int af, const struct netif_port *dev,
                  const union inet_addr *addr, uint8_t plen,
                  const union inet_addr *bcast,
                  uint32_t valid_lft, uint32_t prefered_lft,
                  uint8_t scope)
{
    return ifa_add_set(af, dev, addr, plen, bcast, valid_lft, prefered_lft,
                       scope, 0, false);
}

int inet_addr_del(int af, struct netif_port *dev,
                  const union inet_addr *addr, uint8_t plen)
{
    struct inet_ifaddr *ifa;
    struct inet_device *idev;
    int err;
    char addr_str[64];

    if (!dev || !ifa_prefix_check(af, addr, plen))
        return EDPVS_INVAL;

    idev = dev_get_idev(dev);
    if (!idev)
        return EDPVS_RESOURCE;

    rte_rwlock_write_lock(&in_addr_lock);
    err = __ifa_remove(idev, addr, plen, &ifa, af);
    if (err == EDPVS_OK) {
        dpvs_timer_cancel(&ifa->timer, true);
        if (ifa->flags & IFA_F_SAPOOL)
            sa_pool_destroy(ifa);
        ifa_add_del_mcast(ifa, false);
        ifa_del_route(ifa);
        idev_put(ifa->idev);
        rte_free(ifa);
        rte_atomic32_dec(&idev->ifa_cnt);
        rte_atomic32_dec(&in_addr_cnt);
    }
    rte_rwlock_write_unlock(&in_addr_lock);

    inet_ntop(af, &addr->in.s_addr, addr_str, sizeof(addr_str));
    RTE_LOG(INFO, IFA, "del %s in %s \n", addr_str, __func__);

    idev_put(idev);
    return err;
}

int inet_addr_flush(int af, struct netif_port *dev)
{
    struct inet_device *idev;
    struct inet_ifaddr *ifa, *next;
    char buf[64];

    if ((af != AF_INET && af != AF_INET6) && !dev)
        return EDPVS_INVAL;

    idev = dev_get_idev(dev);
    if (!idev)
        return EDPVS_RESOURCE;

    rte_rwlock_write_lock(&in_addr_lock);

    list_for_each_entry_safe(ifa, next, &idev->ifa_list, d_list) {
        list_del(&ifa->d_list);
        list_del(&ifa->h_list);
        INIT_LIST_HEAD(&ifa->d_list);
        INIT_LIST_HEAD(&ifa->h_list);

        if (rte_atomic32_read(&ifa->refcnt) > 2) {
            RTE_LOG(ERR, IFA, "%s: address %s/%d is in use\n", __func__,
                    inet_ntop(af, &ifa->addr, buf, sizeof(buf)) ? buf : "::",
                    ifa->plen);
            continue;
        }

        dpvs_timer_cancel(&ifa->timer, true);
        if (ifa->flags & IFA_F_SAPOOL)
            sa_pool_destroy(ifa);
        ifa_add_del_mcast(ifa, false);
        ifa_del_route(ifa);
        idev_put(ifa->idev);
        rte_free(ifa);
        rte_atomic32_dec(&idev->ifa_cnt);
        rte_atomic32_dec(&in_addr_cnt);
    }

    rte_rwlock_write_unlock(&in_addr_lock);

    idev_put(idev);
    return EDPVS_OK;
}

static struct netif_port *__inet_addr_get_iface(int af, union inet_addr *addr)
{
    uint32_t hash = in_addr_hash(&addr->in);
    struct inet_ifaddr *ifa;
    struct netif_port *iface = NULL;

    list_for_each_entry(ifa, &in_addr_tab[hash], h_list) {
        if (inet_addr_equal(af, &ifa->addr, addr)) {
            iface = ifa->idev->dev;
            break;
        }
    }

    return iface;
}

struct netif_port *inet_addr_get_iface(int af, union inet_addr *addr)
{
    struct netif_port *dev;

#ifdef INET_ADDR_LOCK
    rte_rwlock_read_lock(&in_addr_lock);
#endif
    dev = __inet_addr_get_iface(af, addr);
#ifdef INET_ADDR_LOCK
    rte_rwlock_read_unlock(&in_addr_lock);
#endif

    return dev;
}

void inet_addr_select(int af, const struct netif_port *dev,
                      const union inet_addr *dst, int scope,
                      union inet_addr *addr)
{
    struct inet_device *idev = dev_get_idev(dev);
    struct inet_ifaddr *ifa;

    if (!addr || !idev)
        return;

    if (af == AF_INET) {
        addr->in.s_addr = htonl(INADDR_ANY);
    } else if (af == AF_INET6) {
        addr->in6 = in6addr_any;
    } else {
        idev_put(idev);
        return;
    }

    rte_rwlock_read_lock(&in_addr_lock);
    /* for each primary address */
    if (af == AF_INET) {
        list_for_each_entry(ifa, &idev->ifa_list, d_list) {
            if ((ifa->flags & IFA_F_SECONDARY) ||
                (ifa->flags & IFA_F_TENTATIVE))
                continue;
            if (ifa->scope > scope)
                continue;
            if (!dst || inet_addr_same_net(af, ifa->plen, dst, &ifa->addr)) {
                *addr = ifa->addr;
                break;
            }

            /* save it and may have better choise later */
            *addr = ifa->addr;
        }
    } else if (af == AF_INET6) {
        ipv6_addr_select(idev, dst, addr);
    }

    /* should we use other interface's address ? */
    rte_rwlock_read_unlock(&in_addr_lock);
    idev_put(idev);
    return;
}

struct inet_ifaddr *inet_addr_ifa_get(int af, const struct netif_port *dev,
                                      union inet_addr *addr)
{
    struct inet_ifaddr *ifa = NULL;
    struct inet_device *idev = NULL;

    assert(addr);
#ifdef INET_ADDR_LOCK
    rte_rwlock_write_lock(&in_addr_lock);
#endif

    if (!dev) {
        dev = __inet_addr_get_iface(af, addr);
        if (!dev)
            goto out;
    }

    idev = dev_get_idev(dev);
    assert(idev);

    ifa = __ifa_lookup(idev, addr, 0, af);
    if (!ifa)
        goto out;

    rte_atomic32_inc(&ifa->refcnt);
out:
#ifdef INET_ADDR_LOCK
    rte_rwlock_write_unlock(&in_addr_lock);
#endif
    if (idev)
        idev_put(idev);
    return ifa;
}

/* support ipv6 only, refer linux:ipv6_chk_mcast_addr */
bool inet_chk_mcast_addr(int af, struct netif_port *dev,
                         const union inet_addr *group,
                         const union inet_addr *src)
{
    struct inet_device *idev = NULL;
    struct inet_ifmcaddr *imc;
    int ret = false;

    if (af != AF_INET6)
        return true;

    idev = dev_get_idev(dev);

    if (idev) {
        rte_rwlock_read_lock(&in_addr_lock);

        imc = __imc_lookup(af, idev, group);
        if (imc){
            if (src && !ipv6_addr_any(&src->in6)) {
            /* TODO: check source-specific multicast (SSM) if @src is assigned */
                ret = true;
            } else {
                ret = true;
            }
        }

        rte_rwlock_read_unlock(&in_addr_lock);
        idev_put(idev);
    }

    return ret;
}

/**
 * control plane
 */
static int ifa_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct inet_addr_param *param = conf;
    struct netif_port *dev;

    if (!conf || size < sizeof(struct inet_addr_param))
        return EDPVS_INVAL;

    if (opt != SOCKOPT_SET_IFADDR_FLUSH) {
        if (!ifa_prefix_check(param->af, &param->addr, param->plen))
            return EDPVS_INVAL;
    }

    dev = netif_port_get_by_name(param->ifname);
    if (!dev) {
        RTE_LOG(WARNING, IFA, "%s: no such device: %s\n",
                __func__, param->ifname);
        return EDPVS_NOTEXIST;
    }

    switch (opt) {
    case SOCKOPT_SET_IFADDR_ADD:
        return inet_addr_add(param->af, dev, &param->addr, param->plen,
                             &param->bcast, param->valid_lft,
                             param->prefered_lft, param->scope, param->flags);

    case SOCKOPT_SET_IFADDR_DEL:
        return inet_addr_del(param->af, dev, &param->addr, param->plen);

    case SOCKOPT_SET_IFADDR_SET:
        return inet_addr_mod(param->af, dev, &param->addr, param->plen,
                             &param->bcast, param->valid_lft,
                             param->prefered_lft, param->scope);

    case SOCKOPT_SET_IFADDR_FLUSH:
        return inet_addr_flush(param->af, dev);

    default:
        return EDPVS_NOTSUPP;
    }
}

static void ifa_fill_param(int af, struct inet_addr_param *param,
                           const struct inet_ifaddr *ifa)
{
    struct sa_pool_stats st;

    param->af       = af;
    param->addr     = ifa->addr;
    param->plen     = ifa->plen;
    param->bcast    = ifa->bcast;
    param->scope    = ifa->scope;
    param->flags    = ifa->flags;
    snprintf(param->ifname, sizeof(param->ifname), "%.15s", ifa->idev->dev->name);

    if (ifa->flags & IFA_F_PERMANENT) {
        param->valid_lft = param->prefered_lft = 0;
    } else {
        struct timeval now, diff;

        dpvs_time_now(&now, true);
        timersub(&now, &ifa->tstemp, &diff);
        param->valid_lft    = ifa->valid_lft - diff.tv_sec;
        param->prefered_lft = ifa->prefered_lft - diff.tv_sec;
    }

    param->sa_used = param->sa_free = param->sa_miss = 0;
    if ((ifa->flags & IFA_F_SAPOOL) && sa_pool_stats(ifa, &st) == EDPVS_OK) {
        param->sa_used  = st.used_cnt;
        param->sa_free  = st.free_cnt;
        param->sa_miss  = st.miss_cnt;
    }
}

static int ifa_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                           void **out, size_t *outsize)
{
    const struct inet_addr_param *param = conf;
    struct inet_addr_param_array *array;
    struct netif_port *dev;
    struct inet_device *idev = NULL;
    struct inet_ifaddr *ifa;
    uint32_t naddr, hash, off;

    if (!conf || size < sizeof(struct inet_addr_param) || !out || !outsize)
        return EDPVS_INVAL;

    if (opt != SOCKOPT_GET_IFADDR_SHOW)
        return EDPVS_NOTSUPP;

    if (param->af != AF_INET &&
        param->af != AF_UNSPEC &&
        param->af != AF_INET6)
        return EDPVS_NOTSUPP;

    if (strlen(param->ifname)) {
        dev = netif_port_get_by_name(param->ifname);
        if (!dev) {
            RTE_LOG(WARNING, IFA, "%s: no such device: %s\n",
                    __func__, param->ifname);
            return EDPVS_NOTEXIST;
        }

        idev = dev_get_idev(dev);
        if (!idev)
            return EDPVS_RESOURCE;
    }

    rte_rwlock_read_lock(&in_addr_lock);

    if (idev)
        naddr = rte_atomic32_read(&idev->ifa_cnt);
    else
        naddr = rte_atomic32_read(&in_addr_cnt);

    *outsize = sizeof(struct inet_addr_param_array) + \
               naddr * sizeof(struct inet_addr_param);
    *out = rte_calloc(NULL, 1, *outsize, RTE_CACHE_LINE_SIZE);
    if (!(*out)) {
        if (idev)
            idev_put(idev);
        rte_rwlock_read_unlock(&in_addr_lock);
        return EDPVS_NOMEM;
    }

    array = *out;
    array->naddr = naddr;
    off = 0;

    if (idev) {
        list_for_each_entry(ifa, &idev->ifa_list, d_list) {
            if (off >= naddr)
                break;
            ifa_fill_param(ifa->af, &array->addrs[off++], ifa);
        }

        idev_put(idev);
    } else {
        for (hash = 0; hash < INET_ADDR_HSIZE; hash++) {
            list_for_each_entry(ifa, &in_addr_tab[hash], h_list) {
                if (off >= naddr)
                    break;
                ifa_fill_param(ifa->af, &array->addrs[off++], ifa);
            }
        }
    }

    rte_rwlock_read_unlock(&in_addr_lock);
    return EDPVS_OK;
}

static struct dpvs_sockopts ifa_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_IFADDR_ADD,
    .set_opt_max    = SOCKOPT_SET_IFADDR_FLUSH,
    .set            = ifa_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_IFADDR_SHOW,
    .get_opt_max    = SOCKOPT_GET_IFADDR_SHOW,
    .get            = ifa_sockopt_get,
};

int inet_addr_init(void)
{
    int err, hash;

    rte_rwlock_init(&in_addr_lock);
    rte_rwlock_write_lock(&in_addr_lock);
    for (hash = 0; hash < INET_ADDR_HSIZE; hash++)
        INIT_LIST_HEAD(&in_addr_tab[hash]);
    rte_rwlock_write_unlock(&in_addr_lock);

    if ((err = sockopt_register(&ifa_sockopts)) != EDPVS_OK)
        return err;

    return EDPVS_OK;
}

int inet_addr_term(void)
{
    int err;

    if ((err = sockopt_unregister(&ifa_sockopts)) != EDPVS_OK)
        return err;

    /* TODO: flush all address */
    return EDPVS_OK;
}
