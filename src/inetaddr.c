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
#include <assert.h>
#include "dpdk.h"
#include "ctrl.h"
#include "netif.h"
#include "netif_addr.h"
#include "timer.h"
#include "sa_pool.h"
#include "ndisc.h"
#include "route.h"
#include "route6.h"
#include "inetaddr.h"
#include "conf/inetaddr.h"

#define IFA
#define RTE_LOGTYPE_IFA         RTE_LOGTYPE_USER1

#define INET_ADDR_HSIZE_SHIFT   8
#define INET_ADDR_HSIZE         (1U << INET_ADDR_HSIZE_SHIFT)

struct ifaddr_action {
    int                 af;
    union inet_addr     addr;
    union inet_addr     bcast;
    uint8_t             plen;
    uint8_t             scope;
    uint32_t            flags;
    uint32_t            valid_lft;
    uint32_t            prefered_lft;
    struct netif_port   *dev;

    ifaddr_ops_t        op;
};

static struct list_head     inet_addr_tab[DPVS_MAX_LCORE][INET_ADDR_HSIZE];
static uint32_t             inet_addr_cnt[DPVS_MAX_LCORE];
static struct list_head     ifa_expired_list[DPVS_MAX_LCORE];
static uint8_t              slave_workers;
static uint64_t             slave_worker_mask;

/* forward declarations */
static void ifa_free(struct inet_ifaddr **ifa_p);
static void fill_ifaddr_action(int af, struct netif_port *dev,
                               const union inet_addr *addr, uint8_t plen,
                               const union inet_addr *bcast,
                               uint32_t valid_lft, uint32_t prefered_lft,
                               uint8_t scope, uint32_t flags, ifaddr_ops_t op,
                               struct ifaddr_action *param);
static int __inet_addr_add(const struct ifaddr_action *param);
static int __inet_addr_del(const struct ifaddr_action *param);
static int __inet_addr_mod(const struct ifaddr_action *param);
static int __inet_addr_flush(const struct ifaddr_action *param);
static int __inet_addr_sync(const struct ifaddr_action *param);
static int inet_addr_sync(const struct ifaddr_action *param);

static uint32_t ifa_msg_seq(void)
{
    static uint32_t counter = 0;        /* for mc msg, called from master only */
    return counter++;
}

static inline struct inet_device *dev_get_idev(const struct netif_port *dev)
{
    assert(dev && dev->in_ptr);
    rte_atomic32_inc(&dev->in_ptr->refcnt);
    return dev->in_ptr;
}

static inline void idev_put(struct inet_device *idev)
{
    rte_atomic32_dec(&idev->refcnt);
}

static inline void imc_hash(struct inet_ifmcaddr *imc, struct inet_device *idev)
{
    list_add(&imc->d_list, &idev->this_ifm_list);
    rte_atomic32_inc(&imc->refcnt);
}

static inline void imc_unhash(struct inet_ifmcaddr *imc)
{
    assert(rte_atomic32_read(&imc->refcnt) > 1);

    list_del(&imc->d_list);
    rte_atomic32_dec(&imc->refcnt);
}

static struct inet_ifmcaddr *imc_lookup(int af, const struct inet_device *idev,
                                        const union inet_addr *maddr)
{
    struct inet_ifmcaddr *imc;
    lcoreid_t cid = rte_lcore_id();

    list_for_each_entry(imc, &idev->ifm_list[cid], d_list) {
        if (inet_addr_equal(af, &imc->addr, maddr)) {
            rte_atomic32_inc(&imc->refcnt);
            return imc;
        }
    }

    return NULL;
}

static void imc_put(struct inet_ifmcaddr *imc)
{
    char ipstr[64];

    if (rte_atomic32_dec_and_test(&imc->refcnt)) {
        RTE_LOG(DEBUG, IFA, "[%02d] %s: del mcaddr %s\n",
                rte_lcore_id(), __func__,
                inet_ntop(imc->af, &imc->addr, ipstr, sizeof(ipstr)));
        /* check unhashed? */
        rte_free(imc);
    }
}

static int idev_mc_add(int af, struct inet_device *idev,
                       const union inet_addr *maddr)
{
    struct inet_ifmcaddr *imc;
    char ipstr[64];

    imc = imc_lookup(af, idev, maddr);
    if (imc) {
        imc_put(imc);
        return EDPVS_EXIST;
    }

    imc = rte_calloc(NULL, 1, sizeof(struct inet_ifmcaddr), RTE_CACHE_LINE_SIZE);
    if (!imc)
        return EDPVS_NOMEM;

    imc->af   = af;
    imc->idev = idev;
    imc->addr = *maddr;
    rte_atomic32_init(&imc->refcnt);

    imc_hash(imc, idev);

    RTE_LOG(DEBUG, IFA, "[%02d] %s: create and add mcaddr %s\n",
            rte_lcore_id(), __func__,
            inet_ntop(af, &imc->addr, ipstr, sizeof(ipstr)));

    return EDPVS_OK;
}

static int idev_mc_del(int af, struct inet_device *idev,
                       const union inet_addr *maddr)
{
    struct inet_ifmcaddr *imc;

    imc = imc_lookup(af, idev, maddr);
    if (!imc)
        return EDPVS_NOTEXIST;

    imc_unhash(imc);
    imc_put(imc);

    return EDPVS_OK;
}

static int ifa_add_del_mcast(struct inet_ifaddr *ifa, bool add)
{
    int err;
    union inet_addr iaddr;
    struct rte_ether_addr eaddr;

    /* for ipv6 only */
    if (ifa->af != AF_INET6)
        return EDPVS_OK;

    memset(&iaddr, 0, sizeof(iaddr));
    memset(&eaddr, 0, sizeof(eaddr));
    addrconf_addr_solict_mult(&ifa->addr.in6, &iaddr.in6);
    ipv6_mac_mult(&iaddr.in6, &eaddr);

    if (add) {
        err = idev_mc_add(ifa->af, ifa->idev, &iaddr);
        if (err && err != EDPVS_EXIST && err != EDPVS_NOTEXIST)
            return err;
        err = netif_mc_add(ifa->idev->dev, &eaddr);
        if (err && err != EDPVS_EXIST && err != EDPVS_NOTEXIST) {
            idev_mc_del(ifa->af, ifa->idev, &iaddr);
            return err;
        }
    } else {
        err = idev_mc_del(ifa->af, ifa->idev, &iaddr);
        if (err && err != EDPVS_EXIST && err != EDPVS_NOTEXIST)
            return err;
        err = netif_mc_del(ifa->idev->dev, &eaddr);
        if (err && err != EDPVS_EXIST && err != EDPVS_NOTEXIST) {
            idev_mc_add(ifa->af, ifa->idev, &iaddr);
            return err;
        }
    }

    return EDPVS_OK;
}

/* add ipv6 multicast address after port start */
int idev_add_mcast_init(void *args)
{
    int err;
    struct inet_device *idev;
    union inet_addr all_nodes, all_routers;
    struct rte_ether_addr eaddr_nodes, eaddr_routers;

    struct netif_port *dev = (struct netif_port *) args;

    idev = dev_get_idev(dev);

    memset(&eaddr_nodes, 0, sizeof(eaddr_nodes));
    memset(&eaddr_routers, 0, sizeof(eaddr_routers));

    memcpy(&all_nodes, &in6addr_linklocal_allnodes, sizeof(all_nodes));
    memcpy(&all_routers, &in6addr_linklocal_allrouters, sizeof(all_routers));

    ipv6_mac_mult(&all_nodes.in6, &eaddr_nodes);
    ipv6_mac_mult(&all_routers.in6, &eaddr_routers);

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

    idev_put(idev);
    return EDPVS_OK;

free_idev_routers:
    idev_mc_del(AF_INET6, idev, &all_routers);
free_netif_nodes:
    netif_mc_del(idev->dev, &eaddr_nodes);
free_idev_nodes:
    idev_mc_del(AF_INET6, idev, &all_nodes);
errout:
    idev_put(idev);
    return err;
}

/* refer to linux:ipv6_chk_mcast_addr */
bool inet_chk_mcast_addr(int af, struct netif_port *dev,
                           const union inet_addr *group,
                           const union inet_addr *src)
{
    int ret;
    struct inet_device *idev;
    struct inet_ifmcaddr *imc;

    /* for ipv6 only */
    if (af != AF_INET6)
        return true;

    idev = dev_get_idev(dev);
    if (unlikely(idev == NULL))
        return false;

    ret = false;
    imc = imc_lookup(af, idev, group);
    if (imc) {
        if (src && !ipv6_addr_any(&src->in6)) {
            /* TODO: check source-specific multicast (SSM) if @src is assigned */
            ret = true;
        } else {
            ret = true;
        }
        imc_put(imc);
    }

    idev_put(idev);

    return ret;
}

static inline bool ifa_prefix_check(int af, const union inet_addr *addr,
                                    uint8_t plen)
{
    if (af != AF_INET && af != AF_INET6)
        return false;

    if (inet_is_addr_any(af, addr))
        return false;

    if ((af == AF_INET && plen > 32) ||
        (af == AF_INET6 && plen > 128))
        return false;

    return true;
}

static inline void ifa_set_lifetime(struct inet_ifaddr *ifa,
                                    uint32_t valid_lft, uint32_t prefered_lft)
{
    /* TODO: support prefered_lft */
    prefered_lft = valid_lft;

    if (!valid_lft)
        ifa->flags |= IFA_F_PERMANENT;
    else
        ifa->flags &= ~IFA_F_PERMANENT;

    ifa->valid_lft      = valid_lft;
    ifa->prefered_lft   = prefered_lft;
}

static uint32_t ifa_hash_key(int af, const union inet_addr *addr)
{
    uint32_t hash, fold;

    fold = inet_addr_fold(af, addr);
    hash = (fold * 0x61C88647) >> (32 - INET_ADDR_HSIZE_SHIFT);

    return hash % INET_ADDR_HSIZE;
}

static struct inet_ifaddr *ifa_lookup(struct inet_device *idev,
                                      const union inet_addr *addr,
                                      uint8_t plen, int af)
{
    struct inet_ifaddr *ifa;

    list_for_each_entry(ifa, &idev->this_ifa_list, d_list) {
        if ((!plen || ifa->plen == plen) && (ifa->af == af)
            && inet_addr_equal(ifa->af, &ifa->addr, addr)) {
            rte_atomic32_inc(&ifa->refcnt);
            return ifa;
        }
    }

    return NULL;
}

static struct inet_ifaddr *expired_ifa_lookup(struct inet_device *idev,
                                              const union inet_addr *addr,
                                              uint8_t plen, int af)
{
    struct inet_ifaddr *ifa;
    lcoreid_t cid = rte_lcore_id();

    list_for_each_entry(ifa, &ifa_expired_list[cid], h_list) {
        if ((!plen || ifa->plen == plen) && (ifa->af == af)
            && inet_addr_equal(af, &ifa->addr, addr)
            && ifa->idev == idev) {
            rte_atomic32_inc(&ifa->refcnt);
            return ifa;
        }
    }

    return NULL;
}

static void ifa_put(struct inet_ifaddr *ifa)
{
    if (rte_atomic32_dec_and_test(&ifa->refcnt)) {
        /* check unhashed? */

        ifa_free(&ifa);
    }
}

static void ifa_hash(struct inet_device *idev, struct inet_ifaddr *ifa)
{
    uint32_t hash;
    lcoreid_t cid = rte_lcore_id();

    /* add to global hash table */
    hash = ifa_hash_key(ifa->af, &ifa->addr);
    list_add(&ifa->h_list, &inet_addr_tab[cid][hash]);
    ++inet_addr_cnt[cid];

    /* add to inet_device's list */
    list_add(&ifa->d_list, &idev->ifa_list[cid]);
    ++idev->ifa_cnt[cid];

    rte_atomic32_inc(&ifa->refcnt);
}

static void ifa_unhash(struct inet_ifaddr *ifa)
{
    lcoreid_t cid = rte_lcore_id();

    assert(rte_atomic32_read(&ifa->refcnt) > 1);

    list_del(&ifa->h_list);
    list_del(&ifa->d_list);

    INIT_LIST_HEAD(&ifa->h_list);
    INIT_LIST_HEAD(&ifa->d_list);

    assert(inet_addr_cnt[cid] > 0 && ifa->idev->ifa_cnt[cid] > 0);
    --inet_addr_cnt[cid];
    --ifa->idev->ifa_cnt[cid];

    /* move @ifa to @ifa_expired_list, and remove it @ifa_free later */
    list_add_tail(&ifa->h_list, &ifa_expired_list[cid]);

    /* free sapool when no one is using it.
     * note ifa may free from here. */
    if (ifa->flags & IFA_F_SAPOOL)
        sa_pool_destroy(ifa);

    rte_atomic32_dec(&ifa->refcnt);
}

struct netif_port *inet_addr_get_iface(int af, union inet_addr *addr)
{
    lcoreid_t cid;
    uint32_t hash;
    struct inet_ifaddr *ifa;

    cid = rte_lcore_id();
    hash = ifa_hash_key(af, addr);

    list_for_each_entry(ifa, &inet_addr_tab[cid][hash], h_list) {
        if (inet_addr_equal(af, &ifa->addr, addr))
            return ifa->idev->dev;
    }

    return NULL;
}

struct inet_ifaddr *inet_addr_ifa_get(int af, const struct netif_port *dev,
                                      union inet_addr *addr)
{
    struct inet_ifaddr *ifa;
    struct inet_device *idev;

    if (!dev) {
        dev = inet_addr_get_iface(af, addr);
        if (!dev)
            return NULL;
    }

    idev = dev_get_idev(dev);
    assert(idev != NULL);

    ifa = ifa_lookup(idev, addr, 0, af);

    idev_put(idev);
    return ifa;
}

struct inet_ifaddr *inet_addr_ifa_get_expired(int af, const struct netif_port *dev,
                                              union inet_addr *addr)
{
    struct inet_ifaddr *ifa;
    struct inet_device *idev;

    if (!dev) {
        dev = inet_addr_get_iface(af, addr);
        if (!dev)
            return NULL;
    }

    idev = dev_get_idev(dev);
    assert(idev != NULL);

    ifa = expired_ifa_lookup(idev, addr, 0, af);

    idev_put(idev);
    return ifa;
}

void inet_addr_ifa_put(struct inet_ifaddr *ifa)
{
    ifa_put(ifa);
}

void inet_addr_select(int af, const struct netif_port *dev,
                      const union inet_addr *dst, int scope,
                      union inet_addr *addr)
{
    struct inet_device *idev;
    struct inet_ifaddr *ifa;
    lcoreid_t cid = rte_lcore_id();

    if (!addr || !dev)
        return;

    idev = dev_get_idev(dev);
    if (unlikely(!idev))
        return;

    switch (af) {
        case AF_INET:
            addr->in.s_addr = htonl(INADDR_ANY);
            list_for_each_entry(ifa, &idev->ifa_list[cid], d_list) {
                if (ifa->af != AF_INET)
                    continue;
                if ((ifa->flags & IFA_F_SECONDARY) ||
                    (ifa->flags & IFA_F_TENTATIVE))
                    continue;
                if (ifa->scope > scope)
                    continue;
                if (!dst || inet_addr_same_net(af, ifa->plen, dst, &ifa->addr)) {
                    *addr = ifa->addr;
                    break;
                }
                /* save it and may have better choice later */
                *addr = ifa->addr;
            }
            break;
        case AF_INET6:
            addr->in6 = in6addr_any;
            ipv6_addr_select(idev, dst, addr);
            break;
        default:
            break;
    }

    idev_put(idev);
}

static int ifa_add_route4(struct inet_ifaddr *ifa)
{
    int err;
    union inet_addr net;

    err = route_add(&ifa->addr.in, 32, RTF_LOCALIN,
                    NULL, ifa->idev->dev, NULL, 0, 0);
    if (err != EDPVS_OK && err != EDPVS_EXIST)
        return err;

    err = inet_addr_net(ifa->af, &ifa->addr, &ifa->mask, &net);
    if (err != EDPVS_OK)
        goto errout;

    if (ifa->plen == 32)
        return EDPVS_OK;

    err = route_add(&net.in, ifa->plen, RTF_FORWARD,
                    NULL, ifa->idev->dev, &ifa->addr.in, 0, 0);
    if (err != EDPVS_OK && err != EDPVS_EXIST)
        goto errout;

    return EDPVS_OK;

errout:
    route_del(&ifa->addr.in, ifa->plen, RTF_LOCALIN,
              NULL, ifa->idev->dev, NULL, 0, 0);
    return err;
}

static int ifa_add_route6(struct inet_ifaddr *ifa)
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
                     &ifa->addr.in6, ifa->idev->dev->mtu);
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
    /* set route from master */
    if (unlikely(rte_lcore_id() != rte_get_main_lcore()))
        return EDPVS_OK;

    switch (ifa->af) {
        case AF_INET:
            return ifa_add_route4(ifa);
        case AF_INET6:
            return ifa_add_route6(ifa);
        default:
            return EDPVS_NOTSUPP;
    }
}

static int ifa_del_route4(struct inet_ifaddr *ifa)
{
    int err;
    union inet_addr net;

    err = route_del(&ifa->addr.in, 32, RTF_LOCALIN,
                    NULL, ifa->idev->dev, NULL, 0, 0);
    if (err != EDPVS_OK && err != EDPVS_NOTEXIST)
        RTE_LOG(WARNING, IFA, "%s: fail to delete localin route\n", __func__);

    if (ifa->plen == 32)
        return EDPVS_OK;

    err = inet_addr_net(ifa->af, &ifa->addr, &ifa->mask, &net);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IFA, "%s: fail to get ip net\n", __func__);

    err = route_del(&net.in, ifa->plen, RTF_FORWARD,
                    NULL, ifa->idev->dev, &ifa->addr.in, 0, 0);
    if (err != EDPVS_OK && err != EDPVS_NOTEXIST)
        RTE_LOG(WARNING, IFA, "%s: fail to delete forward route\n", __func__);

    return EDPVS_OK;
}

static int ifa_del_route6(struct inet_ifaddr *ifa)
{
    int err;
    struct in6_addr net;

    err = route6_del(&ifa->addr.in6, 128, RTF_LOCALIN,
                     &in6addr_any, ifa->idev->dev,
                     &in6addr_any, ifa->idev->dev->mtu);
    if (err != EDPVS_OK && err != EDPVS_NOTEXIST)
        RTE_LOG(WARNING, IFA, "%s: fail to delete localin route\n", __func__);

    if (ifa->plen == 128)
        return EDPVS_OK;

    ipv6_addr_prefix(&net, &ifa->addr.in6, ifa->plen);

    err = route6_del(&net, ifa->plen, RTF_FORWARD,
                     &in6addr_any, ifa->idev->dev,
                     &in6addr_any, ifa->idev->dev->mtu);
    if (err != EDPVS_OK && err != EDPVS_NOTEXIST)
        RTE_LOG(WARNING, IFA, "%s: fail to delete forward route\n", __func__);

    return EDPVS_OK;
}

static int ifa_del_route(struct inet_ifaddr *ifa)
{
    /* set route from master */
    if (unlikely(rte_lcore_id() != rte_get_main_lcore()))
        return EDPVS_OK;

    switch (ifa->af) {
        case AF_INET:
            return ifa_del_route4(ifa);
        case AF_INET6:
            return ifa_del_route6(ifa);
        default:
            return EDPVS_NOTSUPP;
    }
}

static int inet_ifaddr_dad_completed(void *arg)
{
    int err;
    struct ifaddr_action param;
    struct inet_ifaddr *ifa = arg;

    /* only master's ifa scheduled ifa->dad_timer */
    assert(rte_lcore_id() == rte_get_main_lcore());

    dpvs_timer_cancel_nolock(&ifa->dad_timer, true);
    ifa->flags &= ~(IFA_F_TENTATIVE | IFA_F_OPTIMISTIC | IFA_F_DADFAILED);

    /* sync ifa->flags */
    fill_ifaddr_action(ifa->af, ifa->idev->dev, &ifa->addr, ifa->plen, &ifa->bcast,
                       ifa->valid_lft, ifa->prefered_lft, ifa->scope,
                       ifa->flags, INET_ADDR_SYNC, &param);

    err = inet_addr_sync(&param);
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IFA, "%s: inet_addr_sync failed\n", __func__);

    return DTIMER_OK;
}

static void inet_ifaddr_dad_start(struct inet_ifaddr *ifa)
{
    lcoreid_t cid = rte_lcore_id();
    struct timeval tv = {
        .tv_sec     = 3,
        .tv_usec    = 0
    };

    if (ifa->flags & IFA_F_NODAD || !(ifa->flags & IFA_F_TENTATIVE)) {
        ifa->flags &= ~(IFA_F_TENTATIVE | IFA_F_OPTIMISTIC | IFA_F_DADFAILED);
        return;
    }

    ifa->flags |= IFA_F_TENTATIVE | IFA_F_OPTIMISTIC;

    /* timing and sending dad on master only */
    if (cid != rte_get_main_lcore())
        return;

    dpvs_time_rand_delay(&tv, 1000000);
    dpvs_timer_cancel(&ifa->dad_timer, true);
    dpvs_timer_sched(&ifa->dad_timer, &tv, inet_ifaddr_dad_completed, ifa, true);

    ndisc_send_dad(ifa->idev->dev, &ifa->addr.in6);
}

/* called from slave lcore */
void inet_ifaddr_dad_failure(struct inet_ifaddr *ifa)
{
    struct ifaddr_action param;

    if (ifa->flags & IFA_F_PERMANENT) {
        ifa->flags |= IFA_F_DADFAILED;
        fill_ifaddr_action(ifa->af, ifa->idev->dev, &ifa->addr, ifa->plen,
                           &ifa->bcast, ifa->valid_lft, ifa->prefered_lft,
                           ifa->scope, ifa->flags, INET_ADDR_SYNC, &param);
        if (inet_addr_sync(&param) != EDPVS_OK)
            RTE_LOG(ERR, IFA, "[%02d] %s: inet_addr_sync failed\n",
                    rte_lcore_id(), __func__);
    } else if (ifa->flags & IFA_F_TENTATIVE) {
        /* TODO: support privacy addr */
        RTE_LOG(WARNING, IFA, "[%02d] %s: privacy addr is not supported.\n",
                rte_lcore_id(), __func__);
        return;
    } else {
        /* delete ifa from all lcores */
        fill_ifaddr_action(ifa->af, ifa->idev->dev, &ifa->addr, ifa->plen, &ifa->bcast,
                ifa->valid_lft, ifa->prefered_lft, ifa->scope,
                ifa->flags, INET_ADDR_DEL, &param);
        if (inet_addr_sync(&param) != EDPVS_OK)
            RTE_LOG(ERR, IFA, "[%02d] %s: inet_addr_sync failed\n",
                    rte_lcore_id(), __func__);
    }
}

static int ifa_expire(void *arg)
{
    int err;
    lcoreid_t cid = rte_lcore_id();
    struct inet_ifaddr *ifa = (struct inet_ifaddr *)arg;

    /* only master's ifa scheduled ifa->timer */
    assert(cid == rte_get_main_lcore());

    err = inet_addr_del(ifa->af, ifa->idev->dev, &ifa->addr, ifa->plen);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IFA, "inet_addr_del failed\n", __func__);
        return DTIMER_OK;
    }

    return DTIMER_STOP;
}

static int ifa_entry_add(const struct ifaddr_action *param)
{
    int err;
    char ipstr[64];
    struct inet_device *idev;
    struct inet_ifaddr *ifa;
    struct timeval timeo = { 0 };
    bool is_master = (rte_lcore_id() == rte_get_main_lcore());

    if (!param || !param->dev || !ifa_prefix_check(param->af,
                &param->addr, param->plen))
        return EDPVS_INVAL;

    idev = dev_get_idev(param->dev);
    if (!idev)
        return EDPVS_RESOURCE;

    ifa = ifa_lookup(idev, &param->addr, param->plen, param->af);
    if (ifa) {
        ifa_put(ifa);
        err = EDPVS_EXIST;
        goto errout;
    }

    /* reuse expired ifa */
    ifa = expired_ifa_lookup(idev, &param->addr, param->plen, param->af);
    if (ifa) {
        if (ifa->flags & IFA_F_SAPOOL) {
            hold_ifa_sa_pool(ifa); /* hold sa_pool again */
        }
        list_del_init(&ifa->h_list);
        ifa_hash(idev, ifa);
        ifa_put(ifa);

        RTE_LOG(DEBUG, IFA, "[%02d] %s: reuse expired ifaddr %s\n", rte_lcore_id(), __func__,
                inet_ntop(ifa->af, &ifa->addr, ipstr, sizeof(ipstr)));

        return EDPVS_OK;
    }

    ifa = rte_calloc(NULL, 1, sizeof(*ifa), RTE_CACHE_LINE_SIZE);
    if (!ifa) {
        err = EDPVS_NOMEM;
        goto errout;
    }

    ifa->idev   = idev;
    ifa->af     = param->af;
    ifa->addr   = param->addr;
    ifa->plen   = param->plen;
    ifa->bcast  = param->bcast;
    ifa->scope  = param->scope;
    ifa->flags  = param->flags;

    if (param->af == AF_INET)
        inet_plen_to_mask(param->af, param->plen, &ifa->mask);

    rte_atomic32_init(&ifa->refcnt);

    ifa_set_lifetime(ifa, param->valid_lft, param->prefered_lft);
    dpvs_time_now(&ifa->tstemp, is_master); /* mod time */
    dpvs_time_now(&ifa->cstemp, is_master); /* create time */

    err = ifa_add_del_mcast(ifa, true);
    if (err != EDPVS_OK)
        goto free_ifa;

    err = ifa_add_route(ifa);
    if (err != EDPVS_OK && err != EDPVS_EXIST)
        goto del_mc;

    if (ifa->flags & IFA_F_SAPOOL) {
        err = sa_pool_create(ifa, 0, 0);
        if (err != EDPVS_OK)
            goto del_route;
    }

#ifdef CONFIG_TIMER_DEBUG
    snprintf(ifa->timer.name, sizeof(ifa->timer.name), "%s", "ifa_temp_timer");
    snprintf(ifa->dad_timer.name, sizeof(ifa->dad_timer.name), "%s", "ifa_dad_timer");
#endif

    if (!(ifa->flags & IFA_F_PERMANENT)) {
        timeo.tv_sec = ifa->valid_lft;
        if (is_master) {
            dpvs_time_rand_delay(&timeo, 1000000);
            dpvs_timer_sched(&ifa->timer, &timeo, ifa_expire, ifa, true);
        }
    }

    if ((ifa->af == AF_INET6) && (ifa->flags & IFA_F_PERMANENT)) {
        ifa->flags |= IFA_F_TENTATIVE | IFA_F_OPTIMISTIC;
        inet_ifaddr_dad_start(ifa);
    }

    ifa_hash(idev, ifa);

    RTE_LOG(DEBUG, IFA, "[%02d] %s: add ifaddr %s\n", rte_lcore_id(), __func__,
            inet_ntop(ifa->af, &ifa->addr, ipstr, sizeof(ipstr)));

    /* note: hold @idev until ifa deleted */

    return EDPVS_OK;

del_route:
    ifa_del_route(ifa);
del_mc:
    ifa_add_del_mcast(ifa, false);
free_ifa:
    rte_free(ifa);
errout:
    idev_put(idev);
    RTE_LOG(WARNING, IFA, "[%02d] %s: add ifaddr %s failed -- %s\n", rte_lcore_id(), __func__,
            inet_ntop(param->af, &param->addr, ipstr, sizeof(ipstr)), dpvs_strerror(err));
    return err;
}

static int ifa_entry_mod(const struct ifaddr_action *param)
{
    int err;
    char ipstr[64];
    struct inet_device *idev;
    struct inet_ifaddr *ifa;
    struct timeval timeo = { 0 };
    bool is_master = (rte_lcore_id() == rte_get_main_lcore());

    if (!param || !param->dev || !ifa_prefix_check(param->af,
                &param->addr, param->plen))
        return EDPVS_INVAL;

    idev = dev_get_idev(param->dev);
    if (!idev)
        return EDPVS_RESOURCE;

    ifa = ifa_lookup(idev, &param->addr, param->plen, param->af);
    if (!ifa) {
        err = EDPVS_NOTEXIST;
        goto errout;
    }

    dpvs_time_now(&ifa->tstemp, is_master); /* mod time */

    ifa->bcast = param->bcast;
    ifa->scope = param->scope;

    ifa_set_lifetime(ifa, param->valid_lft, param->prefered_lft);
    if (!(ifa->flags & IFA_F_PERMANENT)) {
        timeo.tv_sec = ifa->valid_lft;
        if (is_master) {
            dpvs_timer_cancel(&ifa->timer, true);
            dpvs_time_rand_delay(&timeo, 1000000);
            dpvs_timer_sched(&ifa->timer, &timeo, ifa_expire, ifa, true);
        }
    }

    if ((ifa->af == AF_INET6) && (ifa->flags & IFA_F_PERMANENT)) {
        ifa->flags |= IFA_F_TENTATIVE | IFA_F_OPTIMISTIC;
        inet_ifaddr_dad_start(ifa);
    }

    RTE_LOG(DEBUG, IFA, "[%02d] %s: edit ifaddr %s\n", rte_lcore_id(), __func__,
            inet_ntop(ifa->af, &ifa->addr, ipstr, sizeof(ipstr)));

    ifa_put(ifa);
    idev_put(idev);
    return EDPVS_OK;

errout:
    idev_put(idev);
    RTE_LOG(WARNING, IFA, "[%02d] %s: edit ifaddr %s failed -- %s\n", rte_lcore_id(), __func__,
            inet_ntop(param->af, &param->addr, ipstr, sizeof(ipstr)), dpvs_strerror(err));
    return err;
}

static int ifa_entry_del(const struct ifaddr_action *param)
{
    struct inet_ifaddr *ifa;
    struct inet_device *idev;

    if (!param || !param->dev || !ifa_prefix_check(param->af,
                &param->addr, param->plen))
        return EDPVS_INVAL;

    idev = dev_get_idev(param->dev);
    if (unlikely(!idev))
        return EDPVS_RESOURCE;

    ifa = ifa_lookup(idev, &param->addr, param->plen, param->af);
    if (!ifa) {
        idev_put(idev);
        return EDPVS_NOTEXIST;
    }

    ifa_unhash(ifa);
    ifa_put(ifa);

    idev_put(idev);
    return EDPVS_OK;
}

static int ifa_entry_flush(const struct ifaddr_action *param)
{
    struct inet_ifaddr *ifa, *nxt;
    struct inet_device *idev;
    lcoreid_t cid = rte_lcore_id();

    if (!param || !param->dev)
        return EDPVS_INVAL;

    idev = dev_get_idev(param->dev);
    if (unlikely(!idev))
        return EDPVS_RESOURCE;

    list_for_each_entry_safe(ifa, nxt, &idev->ifa_list[cid], d_list) {
        rte_atomic32_inc(&ifa->refcnt); /* hold @ifa before unhash */
        ifa_unhash(ifa);
        ifa_put(ifa);
    }

    idev_put(idev);
    return EDPVS_OK;
}

static int ifa_entry_sync(const struct ifaddr_action *param)
{
    struct inet_device *idev;
    struct inet_ifaddr *ifa;

    if (!param || !param->dev || !ifa_prefix_check(param->af,
                &param->addr, param->plen))
        return EDPVS_INVAL;

    idev = dev_get_idev(param->dev);
    if (!idev)
        return EDPVS_RESOURCE;

    ifa = ifa_lookup(idev, &param->addr, param->plen, param->af);
    if (!ifa) {
        idev_put(idev);
        return EDPVS_NOTEXIST;
    }

    /* only support snyc flags now */
    ifa->flags = param->flags;
    if ((ifa->flags & IFA_F_DADFAILED) &&
        (rte_lcore_id() == rte_get_main_lcore()))
        dpvs_timer_cancel(&ifa->dad_timer, true);

    ifa_put(ifa);
    idev_put(idev);
    return EDPVS_OK;
}

static void ifa_free(struct inet_ifaddr **ifa_p)
{
    char ipstr[64];
    struct inet_ifaddr *ifa;
    lcoreid_t cid = rte_lcore_id();

    assert(ifa_p != NULL && *ifa_p != NULL);
    ifa = *ifa_p;

    /* remove @ifa from @ifa_expired_list */
    list_del_init(&ifa->h_list);

    if (cid == rte_get_main_lcore()) {
        /* it's safe to cancel timer not pending but zeroed */
        dpvs_timer_cancel(&ifa->dad_timer, true);
        dpvs_timer_cancel(&ifa->timer, true);
    }

    /* note:
     *   sapool has been destroyed when unhash(refer to @ifa_unhash).
     *   If sapool destroyed here, the ifa would not be freed.
     * */

    ifa_add_del_mcast(ifa, false);
    ifa_del_route(ifa);

    /* release @idev held by @ifa */
    idev_put(ifa->idev);

    RTE_LOG(DEBUG, IFA, "[%02d] %s: del ifaddr %s\n", cid, __func__,
            inet_ntop(ifa->af, &ifa->addr, ipstr, sizeof(ipstr)));

    rte_free(ifa);
    *ifa_p = NULL;
}

static void fill_ifaddr_action(int af, struct netif_port *dev,
                               const union inet_addr *addr, uint8_t plen,
                               const union inet_addr *bcast,
                               uint32_t valid_lft, uint32_t prefered_lft,
                               uint8_t scope, uint32_t flags, ifaddr_ops_t op,
                               struct ifaddr_action *param)
{
    if (!param)
        return;
    param->af           = af;
    if (addr)
        param->addr     = *addr;
    if (bcast)
        param->bcast    = *bcast;
    param->plen         = plen;
    param->scope        = scope;
    param->flags        = flags;
    param->valid_lft    = valid_lft;
    param->prefered_lft = prefered_lft;
    param->dev          = dev;

    param->op           = op;
}

static void fill_ifaddr_entry(lcoreid_t cid, const struct inet_ifaddr *ifa, struct inet_addr_data *entry)
{
    entry->ifa_entry.af       = ifa->af;
    entry->ifa_entry.addr     = ifa->addr;
    entry->ifa_entry.bcast    = ifa->bcast;
    entry->ifa_entry.plen     = ifa->plen;
    entry->ifa_entry.scope    = ifa->scope;
    entry->ifa_entry.cid      = cid;
    entry->ifa_entry.flags    = ifa->flags;
    snprintf(entry->ifa_entry.ifname, sizeof(entry->ifa_entry.ifname), "%.15s", ifa->idev->dev->name);

    if (ifa->flags & IFA_F_PERMANENT) {
        entry->ifa_entry.valid_lft    = 0;
        entry->ifa_entry.prefered_lft = 0;
    } else {
        struct timeval now, diff;
        dpvs_time_now(&now, rte_lcore_id() == rte_get_main_lcore());
        timersub(&now, &ifa->tstemp, &diff);
        entry->ifa_entry.valid_lft    = ifa->valid_lft - diff.tv_sec;
        entry->ifa_entry.prefered_lft = ifa->prefered_lft - diff.tv_sec;
    }

    if (ifa->flags & IFA_F_SAPOOL) {
        struct sa_pool_stats st;
        if (get_sa_pool_stats(ifa, &st) == EDPVS_OK) {
            entry->ifa_stats.sa_used = st.used_cnt;
            entry->ifa_stats.sa_free = st.free_cnt;
            entry->ifa_stats.sa_miss = st.miss_cnt;
        }
    }
}

static int copy_lcore_entries(const struct inet_device *idev,
                              int max_entries, struct inet_addr_data_array *array)
{
    int off, hash;
    struct inet_ifaddr *ifa;
    lcoreid_t cid = rte_lcore_id();

    if (!array)
        return EDPVS_INVAL;

    if (!max_entries)
        return EDPVS_OK;    /* no ip configured */

    off = array->naddr;
    if (off >= max_entries)
        return EDPVS_NOROOM;

    if (idev) {
        list_for_each_entry(ifa, &idev->ifa_list[cid], d_list) {
            fill_ifaddr_entry(cid, ifa, &array->addrs[off++]);
            if (off >= max_entries)
                break;
        }
    } else {
        for (hash = 0; hash < INET_ADDR_HSIZE; hash++) {
            list_for_each_entry(ifa, &inet_addr_tab[cid][hash], h_list) {
                fill_ifaddr_entry(cid, ifa, &array->addrs[off++]);
                if (off >= max_entries)
                    break;
            }
        }
    }
    array->naddr = off;

    return EDPVS_OK;
}

static int ifa_msg_get_cb(struct dpvs_msg *msg)
{
    int ifa_cnt, len;
    void *ptr;
    struct inet_device *idev;
    struct inet_addr_data_array *array;
    lcoreid_t cid = rte_lcore_id();

    if (!msg || (msg->len && msg->len != sizeof(idev)))
        return EDPVS_INVAL;
    ptr = msg->len ? (void *)msg->data : NULL;
    idev = ptr ? (*(struct inet_device **)ptr) : NULL;

    if (idev)
        ifa_cnt = idev->ifa_cnt[cid];
    else
        ifa_cnt = inet_addr_cnt[cid];
    len = sizeof(struct inet_addr_data_array) + ifa_cnt * sizeof(struct inet_addr_data);
    array = msg_reply_alloc(len);
    if (unlikely(!array))
        return EDPVS_NOMEM;

    /* zero naddr before copy, do not memset the whole memory for performance */
    array->naddr = 0;

    if (copy_lcore_entries(idev, ifa_cnt, array) != EDPVS_OK)
        RTE_LOG(WARNING, IFA, "[%02d] %s: fail to copy ifa entries\n.", cid, __func__);

    msg->reply.len = len;
    msg->reply.data = array;

    return EDPVS_OK;
}

static int ifa_msg_set_cb(struct dpvs_msg *msg)
{
    struct ifaddr_action *param;

    if (!msg || msg->len != sizeof(*param))
        return EDPVS_INVAL;
    param = (struct ifaddr_action *)msg->data;

    switch (param->op) {
        case INET_ADDR_ADD:
            return ifa_entry_add(param);
        case INET_ADDR_DEL:
            return ifa_entry_del(param);
        case INET_ADDR_MOD:
            return ifa_entry_mod(param);
        case INET_ADDR_FLUSH:
            return ifa_entry_flush(param);
        case INET_ADDR_SYNC:
            return ifa_entry_sync(param);
        case INET_ADDR_GET:
            RTE_LOG(WARNING, IFA, "[%02d] INET_ADDR_GET is not supposed by %s\n",
                    rte_lcore_id(), __func__);
            return EDPVS_INVAL;
        default:
            return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static int ifa_msg_sync_cb(struct dpvs_msg *msg)
{
    struct ifaddr_action *param;

    /* sync from master lcore only */
    assert(rte_lcore_id() == rte_get_main_lcore());

    if (!msg || msg->len != sizeof(*param))
        return EDPVS_INVAL;
    param = (struct ifaddr_action *)msg->data;

    switch (param->op) {
        case INET_ADDR_ADD:
            return __inet_addr_add(param);
        case INET_ADDR_DEL:
            return __inet_addr_del(param);
        case INET_ADDR_MOD:
            return __inet_addr_mod(param);
        case INET_ADDR_FLUSH:
            return __inet_addr_flush(param);
        case INET_ADDR_SYNC:
            return __inet_addr_sync(param);
        case INET_ADDR_GET:
            RTE_LOG(WARNING, IFA, "[%02d] INET_ADDR_GET is not supposed by %s\n",
                    rte_lcore_id(), __func__);
            return EDPVS_INVAL;
        default:
            return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static int __inet_addr_add(const struct ifaddr_action *param)
{
    int err;
    struct dpvs_msg *msg = NULL;

    err = ifa_entry_add(param);
    if (err != EDPVS_OK)
        return err;

    msg = msg_make(MSG_TYPE_IFA_SET, ifa_msg_seq(), DPVS_MSG_MULTICAST,
                   rte_lcore_id(), sizeof(*param), param);
    if (!msg) {
        err = EDPVS_NOMEM;
        goto errout;
    }

    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK)
        goto errout;
    msg_destroy(&msg);

    return EDPVS_OK;

errout:
    if (msg)
        msg_destroy(&msg);
    ifa_entry_del(param);
    return err;
}

int inet_addr_add(int af, struct netif_port *dev,
                  const union inet_addr *addr, uint8_t plen,
                  const union inet_addr *bcast,
                  uint32_t valid_lft, uint32_t prefered_lft,
                  uint8_t scope, uint32_t flags)
{
    struct ifaddr_action param;

    fill_ifaddr_action(af, dev, addr, plen, bcast,
                       valid_lft, prefered_lft, scope,
                       flags, INET_ADDR_ADD, &param);

    return __inet_addr_add(&param);
}

static int __inet_addr_mod(const struct ifaddr_action *param)
{
    int err;
    struct dpvs_msg *msg;

    err = ifa_entry_mod(param);
    if (err != EDPVS_OK)
        return err;

    msg = msg_make(MSG_TYPE_IFA_SET, ifa_msg_seq(), DPVS_MSG_MULTICAST,
                   rte_lcore_id(), sizeof(*param), param);
    if (!msg) {
        RTE_LOG(WARNING, IFA, "%s: msg_make failed\n", __func__);
        return EDPVS_NOMEM;
    }

    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IFA, "%s: multicast_msg_send failed\n", __func__);
    msg_destroy(&msg);

    return err;
}

int inet_addr_mod(int af, struct netif_port *dev,
                  const union inet_addr *addr, uint8_t plen,
                  const union inet_addr *bcast,
                  uint32_t valid_lft, uint32_t prefered_lft,
                  uint8_t scope)
{
    struct ifaddr_action param;

    fill_ifaddr_action(af, dev, addr, plen, bcast,
                       valid_lft, prefered_lft, scope,
                       0, INET_ADDR_MOD, &param);

    return __inet_addr_mod(&param);
}

static int __inet_addr_del(const struct ifaddr_action *param)
{
    int err;
    struct dpvs_msg *msg = NULL;

    err = ifa_entry_del(param);
    if (err != EDPVS_OK)
        return err;

    msg = msg_make(MSG_TYPE_IFA_SET, ifa_msg_seq(), DPVS_MSG_MULTICAST,
                   rte_lcore_id(), sizeof(*param), param);
    if (!msg) {
        err = EDPVS_NOMEM;
        goto errout;
    }

    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK)
        goto errout;
    msg_destroy(&msg);

    return EDPVS_OK;

errout:
    if (msg)
        msg_destroy(&msg);
    ifa_entry_add(param);
    return err;
}

int inet_addr_del(int af, struct netif_port *dev,
                  const union inet_addr *addr, uint8_t plen)
{
    struct ifaddr_action param;

    fill_ifaddr_action(af, dev, addr, plen, NULL,
                       0, 0, 0, 0, INET_ADDR_DEL, &param);

    return __inet_addr_del(&param);
}

static int __inet_addr_flush(const struct ifaddr_action *param)
{
    int err;
    struct dpvs_msg *msg;

    err = ifa_entry_flush(param);
    if (err != EDPVS_OK)
        return err;

    msg = msg_make(MSG_TYPE_IFA_SET, ifa_msg_seq(), DPVS_MSG_MULTICAST,
                   rte_lcore_id(), sizeof(*param), param);
    if (!msg) {
        RTE_LOG(WARNING, IFA, "%s: msg_make failed\n", __func__);
        return EDPVS_NOMEM;
    }

    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IFA, "%s: multicast_msg_send failed\n", __func__);
    msg_destroy(&msg);

    return err;
}

int inet_addr_flush(int af, struct netif_port *dev)
{
    struct ifaddr_action param;

    fill_ifaddr_action(af, dev, NULL, 0, NULL,
                       0, 0, 0, 0, INET_ADDR_FLUSH, &param);

    return __inet_addr_flush(&param);
}

static int __inet_addr_sync(const struct ifaddr_action *param)
{
    int err;
    struct dpvs_msg *msg;

    err = ifa_entry_sync(param);
    if (err != EDPVS_OK)
        return err;

    msg = msg_make(MSG_TYPE_IFA_SET, ifa_msg_seq(), DPVS_MSG_MULTICAST,
                   rte_lcore_id(), sizeof(*param), param);
    if (!msg) {
        RTE_LOG(WARNING, IFA, "%s: msg_make failed\n", __func__);
        return EDPVS_NOMEM;
    }

    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IFA, "%s: multicast_msg_send failed\n", __func__);
    msg_destroy(&msg);

    return err;
}

/*
 * sync ifaddr_action from one slave lcore to master,
 * and then master sync it to all slave lcores, i.e.
 *
 *           unicast msg            mulitcast msg
 * slave(X) --------------> master ----------------> all slaves
 *
 * supported ifaddr_action:
 * - add    : add ifa to all lcores
 * - del    : delete ifa from all lcores
 * - mod    : modify ifa of all lcores
 * - flush  : flush all ifa of all lcores
 * - sync   : sync ifa data to all lcores, only support ifa::flags now
 */
static int inet_addr_sync(const struct ifaddr_action *param)
{
    int err;
    lcoreid_t cid, mid;
    struct dpvs_msg *msg;

    cid = rte_lcore_id();
    mid = rte_get_main_lcore();

    /* call from master */
    if (cid == mid)
        return __inet_addr_sync(param);

    /* call from slave */
    msg = msg_make(MSG_TYPE_IFA_SYNC, 0, DPVS_MSG_UNICAST,
                   cid, sizeof(*param), param);
    if (!msg) {
        RTE_LOG(WARNING, IFA, "[%02d] %s: msg_make failed\n", cid, __func__);
        return EDPVS_NOMEM;
    }

    err = msg_send(msg, rte_get_main_lcore(), DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IFA, "[%02d] %s: msg_send failed\n", cid, __func__);

    return err;
}

static int ifaddr_get_basic(struct inet_device *idev, struct inet_addr_data_array **parray, int *plen)
{
    lcoreid_t cid;
    int ifa_cnt, len, err;
    struct inet_addr_data_array *array;

    /* convey ifa data on master lcore */
    cid = rte_lcore_id();
    assert(cid == rte_get_main_lcore());

    if (idev)
        ifa_cnt = idev->ifa_cnt[cid];
    else
        ifa_cnt = inet_addr_cnt[cid];

    len = sizeof(struct inet_addr_data_array) + ifa_cnt * sizeof(struct inet_addr_data);
    array = rte_calloc(NULL, 1, len, RTE_CACHE_LINE_SIZE);
    if (unlikely(!array))
        return EDPVS_NOMEM;

    err = copy_lcore_entries(idev, ifa_cnt, array);
    if (err != EDPVS_OK) {
        rte_free(array);
        return err;
    }

    *parray = array;
    *plen   = len;
    return EDPVS_OK;
}

static int ifaddr_get_stats(struct inet_device *idev, struct inet_addr_data_array **parray, int *plen)
{
    int ii, err;
    struct inet_addr_data_array *arrmsg, *array;
    struct dpvs_msg *cur, *msg = NULL;
    struct dpvs_multicast_queue *reply = NULL;

    err = ifaddr_get_basic(idev, parray, plen);
    if (err != EDPVS_OK)
        return err;
    array = *parray;

    /* collect ifa sapool stats from slaves */
    if (idev)
        msg = msg_make(MSG_TYPE_IFA_GET, 0, DPVS_MSG_MULTICAST, rte_lcore_id(), sizeof(idev), &idev);
    else
        msg = msg_make(MSG_TYPE_IFA_GET, 0, DPVS_MSG_MULTICAST, rte_lcore_id(), 0, NULL);
    if (!msg) {
        err = EDPVS_NOMEM;
        goto errout;
    }

    err = multicast_msg_send(msg, 0, &reply);
    if (err != EDPVS_OK)
        goto errout;

    list_for_each_entry(cur, &reply->mq, mq_node) {
        arrmsg = (struct inet_addr_data_array *)cur->data;
        if (arrmsg->naddr != array->naddr) {
            RTE_LOG(WARNING, IFA, "%s: ifa naddr does not match -- master=%d, slave[%d]=%d\n",
                    __func__, array->naddr, cur->cid, arrmsg->naddr);
            goto errout;
        }
        for (ii = 0; ii < array->naddr; ii++) {
            assert(memcmp(&array->addrs[ii].ifa_entry.addr,
                          &arrmsg->addrs[ii].ifa_entry.addr,
                          sizeof(union inet_addr)) == 0);
            array->addrs[ii].ifa_stats.sa_used += arrmsg->addrs[ii].ifa_stats.sa_used;
            array->addrs[ii].ifa_stats.sa_free += arrmsg->addrs[ii].ifa_stats.sa_free;
            array->addrs[ii].ifa_stats.sa_miss += arrmsg->addrs[ii].ifa_stats.sa_miss;
        }
    }
    msg_destroy(&msg);
    return EDPVS_OK;

errout:
    if (msg)
        msg_destroy(&msg);
    rte_free(*parray);
    *parray = NULL;
    *plen   = 0;
    return err;
}

static int ifaddr_get_verbose(struct inet_device *idev, struct inet_addr_data_array **parray, int *plen)
{
    lcoreid_t cid;
    int ifa_cnt, len, off, ii, err;
    struct inet_addr_data_array *array, *arrmsg;
    struct dpvs_msg *cur, *msg = NULL;
    struct dpvs_multicast_queue *reply = NULL;

    cid = rte_lcore_id();
    if (idev)
        ifa_cnt = (slave_workers + 1) * idev->ifa_cnt[cid];
    else
        ifa_cnt = (slave_workers + 1) * inet_addr_cnt[cid];

    len = sizeof(struct inet_addr_data_array) + ifa_cnt * sizeof(struct inet_addr_data);
    array = rte_calloc(NULL, 1, len, RTE_CACHE_LINE_SIZE);
    if (unlikely(!array))
        return EDPVS_NOMEM;

    /* master ifa entries */
    err = copy_lcore_entries(idev, ifa_cnt, array);
    if (err != EDPVS_OK)
        goto errout;
    off = array->naddr;

    if (idev)
        msg = msg_make(MSG_TYPE_IFA_GET, 0, DPVS_MSG_MULTICAST, rte_lcore_id(), sizeof(idev), &idev);
    else
        msg = msg_make(MSG_TYPE_IFA_GET, 0, DPVS_MSG_MULTICAST, rte_lcore_id(), 0, NULL);
    if (!msg) {
        err = EDPVS_NOMEM;
        goto errout;
    }

    /* slave ifa entries */
    err = multicast_msg_send(msg, 0, &reply);
    if (err != EDPVS_OK)
        goto errout;
    list_for_each_entry(cur, &reply->mq, mq_node) {
        arrmsg = (struct inet_addr_data_array *)cur->data;
        if (arrmsg->naddr != array->naddr) {
            RTE_LOG(WARNING, IFA, "%s: ifa naddr does not match -- master=%d, slave[%02d]=%d\n",
                    __func__, array->naddr, cur->cid, arrmsg->naddr);
        }
        for (ii = 0; ii < array->naddr && ii < arrmsg->naddr; ii++) {
            if (memcmp(&array->addrs[ii].ifa_entry.addr,
                          &arrmsg->addrs[ii].ifa_entry.addr,
                          sizeof(union inet_addr)) != 0) {
                RTE_LOG(WARNING, IFA, "%s: ifa addr does not match -- master=%X, "
                        "slave[%02d]=%X\n", __func__,
                        array->addrs[ii].ifa_entry.addr, cur->cid,
                        arrmsg->addrs[ii].ifa_entry.addr);
            }
            if (off >= ifa_cnt)
                break;
            memcpy(&array->addrs[off++], &arrmsg->addrs[ii], sizeof(array->addrs[0]));
            array->addrs[ii].ifa_stats.sa_used += arrmsg->addrs[ii].ifa_stats.sa_used;
            array->addrs[ii].ifa_stats.sa_free += arrmsg->addrs[ii].ifa_stats.sa_free;
            array->addrs[ii].ifa_stats.sa_miss += arrmsg->addrs[ii].ifa_stats.sa_miss;
        }
    }
    array->naddr = off;
    msg_destroy(&msg);

    *parray = array;
    *plen   = len;
    return EDPVS_OK;

errout:
    if (msg)
        msg_destroy(&msg);
    rte_free(array);
    *parray = NULL;
    *plen   = 0;
    return err;
}

static int ifa_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    struct netif_port *dev;
    const struct inet_addr_param *param = conf;

    if (!conf || size < sizeof(struct inet_addr_param))
        return EDPVS_INVAL;

    if (opt != SOCKOPT_SET_IFADDR_FLUSH) {
        if (!ifa_prefix_check(param->ifa_entry.af,
                              &param->ifa_entry.addr,
                              param->ifa_entry.plen)) {
            RTE_LOG(WARNING, IFA, "%s: bad %s prefix %d\n", __func__,
                    param->ifa_entry.af == AF_INET ? "ipv4" : "ipv6",
                    param->ifa_entry.plen);
            return EDPVS_INVAL;
        }
    }

    dev = netif_port_get_by_name(param->ifa_entry.ifname);
    if (!dev) {
        RTE_LOG(WARNING, IFA, "%s: device %s not found\n", __func__,
                param->ifa_entry.ifname);
        return EDPVS_NOTEXIST;
    }

    switch (opt) {
        case SOCKOPT_SET_IFADDR_ADD:
            return inet_addr_add(param->ifa_entry.af, dev,
                                 &param->ifa_entry.addr,
                                 param->ifa_entry.plen,
                                 &param->ifa_entry.bcast,
                                 param->ifa_entry.valid_lft,
                                 param->ifa_entry.prefered_lft,
                                 param->ifa_entry.scope,
                                 param->ifa_entry.flags);

        case SOCKOPT_SET_IFADDR_DEL:
            return inet_addr_del(param->ifa_entry.af, dev,
                                 &param->ifa_entry.addr,
                                 param->ifa_entry.plen);

        case SOCKOPT_SET_IFADDR_SET:
            return inet_addr_mod(param->ifa_entry.af, dev,
                                 &param->ifa_entry.addr,
                                 param->ifa_entry.plen,
                                 &param->ifa_entry.bcast,
                                 param->ifa_entry.valid_lft,
                                 param->ifa_entry.prefered_lft,
                                 param->ifa_entry.scope);

        case SOCKOPT_SET_IFADDR_FLUSH:
            return inet_addr_flush(param->ifa_entry.af, dev);

        default:
            return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static int ifa_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                           void **out, size_t *outsize)
{
    int err, len = 0;
    struct netif_port *dev;
    struct inet_device *idev = NULL;
    struct inet_addr_data_array *array = NULL;
    const struct inet_addr_param *param = conf;

    if (!conf || size < sizeof(struct inet_addr_param) || !out || !outsize)
        return EDPVS_INVAL;

    if (opt != SOCKOPT_GET_IFADDR_SHOW)
        return EDPVS_NOTSUPP;

    if (param->ifa_ops != INET_ADDR_GET)
        return EDPVS_INVAL;

    if (param->ifa_entry.af != AF_INET &&
        param->ifa_entry.af != AF_INET6 &&
        param->ifa_entry.af != AF_UNSPEC)
        return EDPVS_NOTSUPP;

    if (strlen(param->ifa_entry.ifname)) {
        dev = netif_port_get_by_name(param->ifa_entry.ifname);
        if (!dev) {
            RTE_LOG(WARNING, IFA, "%s: no such device: %s\n",
                    __func__, param->ifa_entry.ifname);
            return EDPVS_NOTEXIST;
        }

        idev = dev_get_idev(dev);
        if (!idev)
            return EDPVS_RESOURCE;
    }

    if (param->ifa_ops_flags & IFA_F_OPS_VERBOSE)
        err = ifaddr_get_verbose(idev, &array, &len);
    else if (param->ifa_ops_flags & IFA_F_OPS_STATS)
        err = ifaddr_get_stats(idev, &array, &len);
    else
        err = ifaddr_get_basic(idev, &array, &len);

    if (err != EDPVS_OK) {
        RTE_LOG(WARNING, IFA, "%s: fail to get inet addresses -- %s!\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    if (idev)
        idev_put(idev);

    if (array) {
        array->ops = INET_ADDR_GET;
        array->ops_flags = param->ifa_ops_flags;
    }

    *out = array;
    *outsize = len;

    return EDPVS_OK;
}

static struct dpvs_msg_type ifa_msg_types[] = {
    {
        .type               = MSG_TYPE_IFA_GET,
        .prio               = MSG_PRIO_LOW,
        .mode               = DPVS_MSG_MULTICAST,
        .unicast_msg_cb     = ifa_msg_get_cb,
        .multicast_msg_cb   = NULL,
    },
    {
        .type               = MSG_TYPE_IFA_SET,
        .prio               = MSG_PRIO_NORM,
        .mode               = DPVS_MSG_MULTICAST,
        .unicast_msg_cb     = ifa_msg_set_cb,
        .multicast_msg_cb   = NULL,
    },
    {
        .type               = MSG_TYPE_IFA_SYNC,
        .prio               = MSG_PRIO_NORM,
        .mode               = DPVS_MSG_UNICAST,
        //.cid              = rte_get_main_lcore(),
        .unicast_msg_cb     = ifa_msg_sync_cb,
        .multicast_msg_cb   = NULL
    }
};

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
    lcoreid_t cid;
    int err, ii;

    netif_get_slave_lcores(&slave_workers, &slave_worker_mask);

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        for (ii = 0; ii < INET_ADDR_HSIZE; ii++) {
            INIT_LIST_HEAD(&inet_addr_tab[cid][ii]);
        }
        INIT_LIST_HEAD(&ifa_expired_list[cid]);
    }

    ifa_msg_types[2].cid = rte_get_main_lcore();

    if ((err = sockopt_register(&ifa_sockopts)) != EDPVS_OK) {
        RTE_LOG(ERR, IFA, "%s: fail to register ifa_sockopts -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    for (ii = 0; ii < NELEMS(ifa_msg_types); ii++) {
        switch (ifa_msg_types[ii].mode) {
            case DPVS_MSG_UNICAST:
                err = msg_type_register(&ifa_msg_types[ii]);
                break;
            case DPVS_MSG_MULTICAST:
                err = msg_type_mc_register(&ifa_msg_types[ii]);
                break;
            default:
                err = EDPVS_INVAL;
                break;
        }
        if (err != EDPVS_OK) {
            RTE_LOG(ERR, IFA, "%s: fail to register ifa_msg_types[%d] -- %s\n",
                    __func__, ii, dpvs_strerror(err));
            for (--ii; ii >= 0; ii--) {
                switch (ifa_msg_types[ii].mode) {
                    case DPVS_MSG_UNICAST:
                        msg_type_unregister(&ifa_msg_types[ii]);
                        break;
                    case DPVS_MSG_MULTICAST:
                        msg_type_mc_unregister(&ifa_msg_types[ii]);
                        break;
                }
            }
            sockopt_unregister(&ifa_sockopts);
            return err;
        }
    }

    return EDPVS_OK;
}

int inet_addr_term(void)
{
    int ii, err = EDPVS_OK;

    /* TODO: flush all address */

    if ((err = sockopt_unregister(&ifa_sockopts)) != EDPVS_OK) {
        RTE_LOG(ERR, IFA, "%s: fail to unregister ifa_sockopts -- %s\n",
                __func__, dpvs_strerror(err));
    }

    for (ii = 0; ii < NELEMS(ifa_msg_types); ii++) {
        switch (ifa_msg_types[ii].mode) {
            case DPVS_MSG_UNICAST:
                err = msg_type_unregister(&ifa_msg_types[ii]);
                break;
            case DPVS_MSG_MULTICAST:
                err = msg_type_mc_unregister(&ifa_msg_types[ii]);
                break;
            default:
                err = EDPVS_INVAL;
                break;
        }
        if (err != EDPVS_OK)
            RTE_LOG(ERR, IFA, "%s: fail to unregister ifa_msg_types[%d] -- %s\n",
                    __func__, ii, dpvs_strerror(err));
    }

    return err;
}
