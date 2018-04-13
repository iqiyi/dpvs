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
#include "conf/inetaddr.h"

#define IFA
#define RTE_LOGTYPE_IFA             RTE_LOGTYPE_USER1

#define INET_ADDR_HSIZE_SHIFT       8
#define INET_ADDR_HSIZE             (1U << INET_ADDR_HSIZE_SHIFT)

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
                                        uint8_t plen)
{
    struct inet_ifaddr *ifa;

    list_for_each_entry(ifa, &idev->ifa_list, d_list) {
        if ((!plen || ifa->plen == plen)
                && inet_addr_equal(idev->af, &ifa->addr, addr)) {
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
                        uint8_t plen, struct inet_ifaddr **ifa)
{
    struct inet_ifaddr *ent;

    if ((ent = __ifa_lookup(idev, addr, plen)) == NULL)
        return EDPVS_NOTEXIST;

    if (rte_atomic32_read(&ent->refcnt) > 2)
        return EDPVS_BUSY;

    ___ifa_remove(ent);

    if (ifa)
        *ifa = ent;
    return EDPVS_OK;
}

static int ifa_add_route(struct inet_ifaddr *ifa)
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

    err = inet_addr_net(ifa->idev->af, &ifa->addr, &ifa->mask, &net);
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

static int ifa_del_route(struct inet_ifaddr *ifa)
{
    int err;
    union inet_addr net;

    err = route_del(&ifa->addr.in, 32, RTF_LOCALIN, 
                    NULL, ifa->idev->dev, NULL, 0, 0);
    if (err != EDPVS_OK && err != EDPVS_NOTEXIST)
        RTE_LOG(WARNING, IFA, "%s: fail to delete route", __func__);

    if (ifa->plen == 32)
        return EDPVS_OK;

    err = inet_addr_net(ifa->idev->af, &ifa->addr, &ifa->mask, &net);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IFA, "%s: fail to delete route", __func__);

    err = route_del(&net.in, ifa->plen, RTF_FORWARD, 
                    NULL, ifa->idev->dev, &ifa->addr.in, 0, 0);
    if (err != EDPVS_OK && err != EDPVS_NOTEXIST)
        RTE_LOG(WARNING, IFA, "%s: fail to delete route", __func__);

    return EDPVS_OK;
}

static void ifa_expire(void *arg)
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
        return;
    }

    list_del(&ifa->d_list);
    list_del(&ifa->h_list);
    INIT_LIST_HEAD(&ifa->d_list);
    INIT_LIST_HEAD(&ifa->h_list);

    dpvs_timer_cancel(&ifa->timer, true);
    if (ifa->flags & IFA_F_SAPOOL)
        sa_pool_destroy(ifa);
    ifa_del_route(ifa);
    idev_put(ifa->idev);
    rte_atomic32_dec(&ifa->idev->ifa_cnt);
    rte_free(ifa);
    rte_atomic32_dec(&in_addr_cnt);

    rte_rwlock_write_unlock(&in_addr_lock);
    return;
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

    if (!dev || !ifa_prefix_check(af, addr, plen))
        return EDPVS_INVAL;

    idev = dev_get_idev(dev);
    if (!idev)
        return EDPVS_RESOURCE;

    rte_rwlock_write_lock(&in_addr_lock);

    ifa = __ifa_lookup(idev, addr, plen);
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

        ifa->idev = idev;
        ifa->addr = *addr;
        ifa->plen = plen;
        ifa->flags = flags;
        inet_plen_to_mask(af, plen, &ifa->mask);
        dpvs_time_now(&ifa->cstemp, true);
        rte_atomic32_init(&ifa->refcnt);

        /* set routes for local and network */
        err = ifa_add_route(ifa);
        if (err != EDPVS_OK)
            goto free_ifa;

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

    rte_rwlock_write_unlock(&in_addr_lock);
    idev_put(idev);
    return EDPVS_OK;

rem_ifa:
    ___ifa_remove(ifa);
del_route:
    ifa_del_route(ifa);
free_ifa:
    rte_free(ifa);
errout:
    rte_rwlock_write_unlock(&in_addr_lock);
    idev_put(idev);
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

    if (!dev || !ifa_prefix_check(af, addr, plen))
        return EDPVS_INVAL;

    idev = dev_get_idev(dev);
    if (!idev)
        return EDPVS_RESOURCE;

    rte_rwlock_write_lock(&in_addr_lock);
    err = __ifa_remove(idev, addr, plen, &ifa);
    if (err == EDPVS_OK) {
        dpvs_timer_cancel(&ifa->timer, true);
        if (ifa->flags & IFA_F_SAPOOL)
            sa_pool_destroy(ifa);
        ifa_del_route(ifa);
        idev_put(ifa->idev);
        rte_free(ifa);
        rte_atomic32_dec(&idev->ifa_cnt);
        rte_atomic32_dec(&in_addr_cnt);
    }
    rte_rwlock_write_unlock(&in_addr_lock);

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

    if (af == AF_INET)
        addr->in.s_addr = htonl(INADDR_ANY);
    else {
        addr->in6 = in6addr_any;
        return; /* not support IPv6 now */
    }

    if (!idev)
        return;

    rte_rwlock_read_lock(&in_addr_lock);
    /* for each primary address */
    list_for_each_entry(ifa, &idev->ifa_list, d_list) {
        if (ifa->flags & IFA_F_SECONDARY)
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

    /* should we use other interface's address ? */
    rte_rwlock_read_unlock(&in_addr_lock);
    return;
}

struct inet_ifaddr *inet_addr_ifa_get(int af, const struct netif_port *dev,
                                      union inet_addr *addr)
{
	struct inet_ifaddr *ifa = NULL;
	struct inet_device *idev = NULL;

	assert(af == AF_INET && addr);

#ifdef INET_ADDR_LOCK
	rte_rwlock_write_lock(&in_addr_lock);
#endif

	if (!dev) {
		dev = __inet_addr_get_iface(AF_INET, addr);
		if (!dev)
			goto out;
	}

	idev = dev_get_idev(dev);
	assert(idev);

	ifa = __ifa_lookup(idev, addr, 0);
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

    if (param->af != AF_INET && param->af != AF_UNSPEC)
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
            ifa_fill_param(idev->af, &array->addrs[off++], ifa);
        }

        idev_put(idev);
    } else {
        for (hash = 0; hash < INET_ADDR_HSIZE; hash++) {
            list_for_each_entry(ifa, &in_addr_tab[hash], h_list) {
                if (off >= naddr)
                    break;
                ifa_fill_param(AF_INET, &array->addrs[off++], ifa);
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
