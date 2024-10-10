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
/**
 * netif unicast multicast hw address list setting.
 * XXX: currently, support multicast list only.
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#include "netif.h"
#include "netif_addr.h"
#include "conf/netif_addr.h"
#include "kni.h"

int __netif_hw_addr_add(struct netif_hw_addr_list *list,
        const struct rte_ether_addr *addr, uint16_t flags)
{
    struct netif_hw_addr *ha;

    list_for_each_entry(ha, &list->addrs, list) {
        if (eth_addr_equal(&ha->addr, addr)) {
            rte_atomic32_inc(&ha->refcnt);
            ha->flags |= flags;
            return EDPVS_OK;
        }
    }

    ha = rte_zmalloc(NULL, sizeof(*ha), 0);
    if (!ha)
        return EDPVS_NOMEM;

    rte_ether_addr_copy(addr, &ha->addr);
    rte_atomic32_set(&ha->refcnt, 1);
    ha->flags = flags;
    list_add_tail(&ha->list, &list->addrs);
    list->count++;

    return EDPVS_OK;
}

int __netif_hw_addr_del(struct netif_hw_addr_list *list,
        const struct rte_ether_addr *addr, uint16_t flags)
{
    struct netif_hw_addr *ha, *n;

    list_for_each_entry_safe(ha, n, &list->addrs, list) {
        if (eth_addr_equal(&ha->addr, addr)) {
            if (rte_atomic32_dec_and_test(&ha->refcnt)) {
                list_del(&ha->list);
                list->count--;
                rte_free(ha);
            } else {
                ha->flags &= ~flags;
            }
            return EDPVS_OK;
        }
    }

    return EDPVS_NOTEXIST;
}

static int __netif_hw_addr_sync(struct netif_hw_addr_list *to,
                                struct netif_hw_addr_list *from,
                                struct netif_port *todev)
{
    struct netif_hw_addr *ha, *n;
    int err = EDPVS_OK;
    char mac[18];

    list_for_each_entry_safe(ha, n, &from->addrs, list) {
        eth_addr_dump(&ha->addr, mac, sizeof(mac)); /* for debug */

        if (!ha->sync_cnt) { /* not synced to lower device */
            err = __netif_hw_addr_add(to, &ha->addr, 0);
            if (err == EDPVS_OK) {
                ha->sync_cnt++;
                rte_atomic32_inc(&ha->refcnt);
                RTE_LOG(DEBUG, NETIF, "%s: sync %s to %s OK!\n",
                        __func__, mac, todev->name);
            } else {
                RTE_LOG(ERR, NETIF, "%s: sync %s to %s FAIL!\n",
                        __func__, mac, todev->name);
                break;
            }
        } else if (rte_atomic32_read(&ha->refcnt) == 1) {
            /* both "ha->sync_cnt != 0" and "refcnt == 1" means
             * lower device is the only reference of this ha.
             * we can "unsync" from lower dev and remove it for upper. */
            err = __netif_hw_addr_del(to, &ha->addr, 0);
            if (err == EDPVS_OK) {
                RTE_LOG(DEBUG, NETIF, "%s: unsync %s to %s OK!\n",
                        __func__, mac, todev->name);
                list_del(&ha->list);
                rte_free(ha);
                from->count--;

            } else {
                RTE_LOG(ERR, NETIF, "%s: unsync %s to %s FAIL!\n",
                        __func__, mac, todev->name);
                break;
            }
        }
    }

    return err;
}

static int __netif_hw_addr_unsync(struct netif_hw_addr_list *to,
                                  struct netif_hw_addr_list *from)
{
    /* TODO: */
    return EDPVS_INVAL;
}

static int __netif_hw_addr_sync_multiple(struct netif_hw_addr_list *to,
                                         struct netif_hw_addr_list *from,
                                         struct netif_port *todev,
                                         int sync_cnt)
{
    struct netif_hw_addr *ha, *n;
    int err = EDPVS_OK;
    char mac[18];

    list_for_each_entry_safe(ha, n, &from->addrs, list) {
        eth_addr_dump(&ha->addr, mac, sizeof(mac)); /* for debug */

        if (rte_atomic32_read(&ha->refcnt) == ha->sync_cnt) {
            /* 'ha->refcnt == ha->sync_cnt' means the 'ha' has been removed from currecnt device
             * and all references of this ha are from lower devices, so it's time to unsync. */
            err = __netif_hw_addr_del(to, &ha->addr, 0);
            if (err == EDPVS_OK) {
                RTE_LOG(DEBUG, NETIF, "%s: unsync %s to %s OK!\n",
                        __func__, mac, todev->name);
                ha->sync_cnt--;
                if (rte_atomic32_dec_and_test(&ha->refcnt)) {
                    list_del(&ha->list);
                    rte_free(ha);
                    from->count--;
                }
            } else {
                RTE_LOG(ERR, NETIF, "%s: unsync %s to %s FAIL!\n",
                        __func__, mac, todev->name);
                break;
            }
        } else if (ha->sync_cnt < sync_cnt) {
            /* sync to lower devices only once */
            err = __netif_hw_addr_add(to, &ha->addr, 0);
            if (err == EDPVS_OK) {
                ha->sync_cnt++;
                rte_atomic32_inc(&ha->refcnt);
                RTE_LOG(DEBUG, NETIF, "%s: sync %s to %s OK!\n",
                        __func__, mac, todev->name);
            } else {
                break;
            }
        }
    }

    return err;
}

static int __netif_hw_addr_unsync_multiple(struct netif_hw_addr_list *to,
                                           struct netif_hw_addr_list *from,
                                           int sync_cnt)
{
    /* TODO: */
    return EDPVS_INVAL;
}

int __netif_set_mc_list(struct netif_port *dev)
{
    if (!dev->netif_ops->op_set_mc_list)
        return EDPVS_NOTSUPP;

    return dev->netif_ops->op_set_mc_list(dev);
}

int netif_set_mc_list(struct netif_port *dev)
{
    int err;

    rte_rwlock_write_lock(&dev->dev_lock);
    err = __netif_set_mc_list(dev);
    rte_rwlock_write_unlock(&dev->dev_lock);

    return err;
}

int netif_mc_add(struct netif_port *dev, const struct rte_ether_addr *addr)
{
    int err;

    rte_rwlock_write_lock(&dev->dev_lock);
    err = __netif_hw_addr_add(&dev->mc, addr, 0);
    if (err == EDPVS_OK)
        err = __netif_set_mc_list(dev);
    rte_rwlock_write_unlock(&dev->dev_lock);

    return err;
}

int netif_mc_del(struct netif_port *dev, const struct rte_ether_addr *addr)
{
    int err;

    rte_rwlock_write_lock(&dev->dev_lock);
    err = __netif_hw_addr_del(&dev->mc, addr, 0);
    if (err == EDPVS_OK)
        err = __netif_set_mc_list(dev);
    rte_rwlock_write_unlock(&dev->dev_lock);

    return err;
}

void netif_mc_flush(struct netif_port *dev)
{
    struct netif_hw_addr *ha, *n;

    rte_rwlock_write_lock(&dev->dev_lock);
    list_for_each_entry_safe(ha, n, &dev->mc.addrs, list) {
        if (rte_atomic32_dec_and_test(&ha->refcnt)) {
            list_del(&ha->list);
            rte_free(ha);
            dev->mc.count--;
        }
    }

    __netif_set_mc_list(dev);
    rte_rwlock_write_unlock(&dev->dev_lock);
}

void netif_mc_init(struct netif_port *dev)
{
    rte_rwlock_write_lock(&dev->dev_lock);
    INIT_LIST_HEAD(&dev->mc.addrs);
    dev->mc.count = 0;
    rte_rwlock_write_unlock(&dev->dev_lock);
}

int __netif_mc_dump(struct netif_port *dev, uint16_t filter_flags,
        struct rte_ether_addr *addrs, size_t *naddr)
{
    struct netif_hw_addr *ha;
    int off = 0;

    if (*naddr < dev->mc.count)
        return EDPVS_NOROOM;

    list_for_each_entry(ha, &dev->mc.addrs, list)
        if (!filter_flags || ha->flags & filter_flags)
            rte_ether_addr_copy(&ha->addr, &addrs[off++]);

    *naddr = off;
    return EDPVS_OK;
}

int netif_mc_dump(struct netif_port *dev, uint16_t filter_flags,
        struct rte_ether_addr *addrs, size_t *naddr)
{
    int err;

    rte_rwlock_read_lock(&dev->dev_lock);
    err = __netif_mc_dump(dev, filter_flags, addrs, naddr);
    rte_rwlock_read_unlock(&dev->dev_lock);

    return err;
}

static int __netif_mc_dump_all(struct netif_port *dev, uint16_t filter_flags,
        struct netif_hw_addr_entry *addrs, int *naddr)
{
    struct netif_hw_addr *ha;
    int off = 0;

    if (*naddr < dev->mc.count)
        return EDPVS_NOROOM;

    list_for_each_entry(ha, &dev->mc.addrs, list) {
        eth_addr_dump(&ha->addr, addrs[off].addr, sizeof(addrs[off].addr));
        addrs[off].refcnt = rte_atomic32_read(&ha->refcnt);
        addrs[off].flags = ha->flags;
        addrs[off].sync_cnt = ha->sync_cnt;
        off++;
    }

    *naddr = off;
    return EDPVS_OK;
}

int __netif_mc_print(struct netif_port *dev,
                     char *buf, int *len, int *pnaddr)
{
    struct netif_hw_addr_entry addrs[NETIF_MAX_HWADDR];
    int naddr = NELEMS(addrs);
    int err, i;
    int strlen = 0;

    err = __netif_mc_dump_all(dev, 0, addrs, &naddr);
    if (err != EDPVS_OK)
        goto errout;

    for (i = 0; i < naddr && *len > strlen; i++) {
        err = snprintf(buf + strlen, *len - strlen,
                "        link %s %srefcnt %d, synced %d\n",
                addrs[i].addr,
                addrs[i].flags & HW_ADDR_F_FROM_KNI ? "(kni) ": "",
                addrs[i].refcnt, addrs[i].sync_cnt);
        if (err < 0) {
            err = EDPVS_NOROOM;
            goto errout;
        }
        strlen += err;
    }

    *len = strlen;
    *pnaddr = naddr;
    return EDPVS_OK;

errout:
    *len = 0;
    *pnaddr = 0;
    buf[0] = '\0';
    return err;
}

int netif_get_multicast_addrs(struct netif_port *dev, void **out, size_t *outlen)
{
    int err;
    size_t len;
    struct netif_hw_addr_array *array;

    rte_rwlock_read_lock(&dev->dev_lock);
    len = sizeof(*array) + dev->mc.count * sizeof(struct netif_hw_addr_entry);
    array = rte_zmalloc(NULL, len, RTE_CACHE_LINE_SIZE);
    if (unlikely(!array)) {
        err = EDPVS_NOMEM;
    } else {
        array->count = dev->mc.count;
        err = __netif_mc_dump_all(dev, 0, array->entries, &array->count);
    }
    rte_rwlock_read_unlock(&dev->dev_lock);

    if (err != EDPVS_OK) {
        *out = NULL;
        *outlen = 0;
    } else {
        *out = array;
        *outlen = len;
    }
    return err;
}

int netif_mc_print(struct netif_port *dev,
                     char *buf, int *len, int *pnaddr)
{
    int err;

    rte_rwlock_read_lock(&dev->dev_lock);
    err = __netif_mc_print(dev, buf, len, pnaddr);
    rte_rwlock_read_unlock(&dev->dev_lock);

    return err;
}

int __netif_mc_sync(struct netif_port *to, struct netif_port *from)
{
    int err;

    err = __netif_hw_addr_sync(&to->mc, &from->mc, to);
    if (err == EDPVS_OK)
        err = __netif_set_mc_list(to);

    return err;
}

/* call from netif_ops.set_mc_addr_list of layered virtual devices. */
int netif_mc_sync(struct netif_port *to, struct netif_port *from)
{
    int err;

    rte_rwlock_write_lock(&to->dev_lock);
    rte_rwlock_write_lock(&from->dev_lock);

    err = __netif_mc_sync(to, from);

    rte_rwlock_write_unlock(&from->dev_lock);
    rte_rwlock_write_unlock(&to->dev_lock);

    return err;
}

int __netif_mc_unsync(struct netif_port *to, struct netif_port *from)
{
    int err;

    err = __netif_hw_addr_unsync(&to->mc, &from->mc);
    if (err == EDPVS_OK)
        err = __netif_set_mc_list(to);

    return err;
}

int netif_mc_unsync(struct netif_port *to, struct netif_port *from)
{
    int err;

    rte_rwlock_write_lock(&to->dev_lock);
    rte_rwlock_write_lock(&from->dev_lock);

    err = __netif_mc_unsync(to, from);

    rte_rwlock_write_unlock(&from->dev_lock);
    rte_rwlock_write_unlock(&to->dev_lock);

    return err;
}

int __netif_mc_sync_multiple(struct netif_port *to, struct netif_port *from, int sync_cnt)
{
    int err;

    err = __netif_hw_addr_sync_multiple(&to->mc, &from->mc, to, sync_cnt);
    if (err == EDPVS_OK)
        err = __netif_set_mc_list(to);

    return err;
}

int netif_mc_sync_multiple(struct netif_port *to,
                           struct netif_port *from,
                           int sync_cnt)
{
    int err;

    rte_rwlock_write_lock(&to->dev_lock);
    rte_rwlock_write_lock(&from->dev_lock);

    err = __netif_mc_sync_multiple(to, from, sync_cnt);

    rte_rwlock_write_unlock(&from->dev_lock);
    rte_rwlock_write_unlock(&to->dev_lock);

    return err;
}

int __netif_mc_unsync_multiple(struct netif_port *to,
                               struct netif_port *from,
                               int sync_cnt)
{
    int err;

    err = __netif_hw_addr_unsync_multiple(&to->mc, &from->mc, sync_cnt);
    if (err == EDPVS_OK)
        err = __netif_set_mc_list(to);

    return err;
}

int netif_mc_unsync_multiple(struct netif_port *to, struct netif_port *from, int sync_cnt)
{
    int err;

    rte_rwlock_write_lock(&to->dev_lock);
    rte_rwlock_write_lock(&from->dev_lock);

    err = __netif_mc_unsync_multiple(to, from, sync_cnt);

    rte_rwlock_write_unlock(&from->dev_lock);
    rte_rwlock_write_unlock(&to->dev_lock);

    return err;
}
