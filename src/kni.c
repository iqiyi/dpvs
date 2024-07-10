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
 * DPDK KNI device management.
 *
 * KNI device should be add/del by request. And any real devices,
 * can be attached on. Such as dpdk phy device, dpdk bonding
 * device and even virtual vlan device.
 *
 * raychen@qiyi.com, June 2017, initial.
 */
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "conf/common.h"
#include "dpdk.h"
#include "netif.h"
#include "conf/netif_addr.h"
#include "ctrl.h"
#include "kni.h"
#include "vlan.h"
#include "conf/kni.h"
#include "conf/sockopts.h"

#define Kni /* KNI is defined */
#define RTE_LOGTYPE_Kni     RTE_LOGTYPE_USER1

#define KNI_RX_RING_ELEMS       2048
bool g_kni_enabled = true;

static void kni_fill_conf(const struct netif_port *dev, const char *ifname,
                          struct rte_kni_conf *conf)
{
    struct rte_eth_dev_info info = {0};

    memset(conf, 0, sizeof(*conf));
    conf->group_id = dev->id;
    conf->mbuf_size = rte_pktmbuf_data_room_size(pktmbuf_pool[dev->socket]) - RTE_PKTMBUF_HEADROOM;

    /*
     * kni device should use same mac as real device,
     * because it may config same IP of real device.
     * diff mac means kni cannot accept packets sent
     * to real-device.
     */
    memcpy(conf->mac_addr, dev->addr.addr_bytes, sizeof(conf->mac_addr));

    if (dev->type == PORT_TYPE_GENERAL) { /* dpdk phy device */
        rte_eth_dev_info_get(dev->id, &info);
#if RTE_VERSION < RTE_VERSION_NUM(18, 11, 0, 0)
        conf->addr = info.pci_dev->addr;
        conf->id = info.pci_dev->id;
#else
        if (info.device) {
            const struct rte_bus *bus = NULL;
            const struct rte_pci_device *pci_dev;
            bus = rte_bus_find_by_device(info.device);
            if (bus && !strcmp(bus->name, "pci")) {
                pci_dev = RTE_DEV_TO_PCI(info.device);
                conf->addr = pci_dev->addr;
                conf->id = pci_dev->id;
            }
        }
#endif
    }

    if (ifname && strlen(ifname))
        snprintf(conf->name, sizeof(conf->name), "%s", ifname);
    else
        snprintf(conf->name, sizeof(conf->name), "%s.kni", dev->name);

    return;
}

static int kni_mc_list_cmp_set(struct netif_port *dev,
                               struct rte_ether_addr *addrs, size_t naddr)
{
    int err = EDPVS_INVAL, i, j;
    struct rte_ether_addr addrs_old[NETIF_MAX_HWADDR];
    size_t naddr_old;
    char mac[64];
    struct mc_change_list {
        size_t                  naddr;
        struct rte_ether_addr   addrs[NETIF_MAX_HWADDR*2];
        /* state: 0 - unchanged, 1 - added, 2 deleted. */
        int                     states[NETIF_MAX_HWADDR*2];
    } chg_lst = {0};

    rte_rwlock_write_lock(&dev->dev_lock);

    naddr_old = NELEMS(addrs_old);
    err = __netif_mc_dump(dev, HW_ADDR_F_FROM_KNI, addrs_old, &naddr_old);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: fail to get current mc list\n", __func__);
        goto out;
    }

    /* make sure change list not overflow. */
    if (naddr > NETIF_MAX_HWADDR || naddr_old > NETIF_MAX_HWADDR) {
        err = EDPVS_NOROOM;
        goto out;
    }

    RTE_LOG(DEBUG, Kni, "dev %s link mcast:\n", dev->name);

    /* add all addrs from netlink(linux) to change-list and
     * assume they're all new added by default. */
    for (i = 0; i < naddr; i++) {
        rte_ether_addr_copy(&addrs[i], &chg_lst.addrs[i]);
        chg_lst.states[i] = 1;

        RTE_LOG(DEBUG, Kni, "    new [%02d] %s\n", i,
                eth_addr_dump(&addrs[i], mac, sizeof(mac)));
    }
    chg_lst.naddr = naddr;

    /* now check for old mc list */
    for (i = 0; i < naddr_old; i++) {
        RTE_LOG(DEBUG, Kni, "    old [%02d] %s\n", i,
                eth_addr_dump(&addrs_old[i], mac, sizeof(mac)));

        for (j = 0; j < chg_lst.naddr; j++) {
            if (eth_addr_equal(&addrs_old[i], &chg_lst.addrs[j])) {
                /* already exist */
                chg_lst.states[j] = 0;
                break;
            }
        }
        if (j == chg_lst.naddr) {
            /* deleted */
            assert(chg_lst.naddr < NETIF_MAX_HWADDR * 2);

            rte_ether_addr_copy(&addrs_old[i], &chg_lst.addrs[chg_lst.naddr]);
            chg_lst.states[chg_lst.naddr] = 2;
            chg_lst.naddr++;
        }
    }

    /* config mc list according to change list */
    for (i = 0; i < chg_lst.naddr; i++) {
        switch (chg_lst.states[i]) {
        case 0:
            /* nothing */
            break;
        case 1:
            err = __netif_hw_addr_add(&dev->mc, &chg_lst.addrs[i], HW_ADDR_F_FROM_KNI);

            RTE_LOG(INFO, Kni, "%s: add mc addr: %s %s %s\n", __func__,
                    eth_addr_dump(&chg_lst.addrs[i], mac, sizeof(mac)),
                    dev->name, dpvs_strerror(err));
            break;
        case 2:
            err = __netif_hw_addr_del(&dev->mc, &chg_lst.addrs[i], HW_ADDR_F_FROM_KNI);

            RTE_LOG(INFO, Kni, "%s: del mc addr: %s %s %s\n", __func__,
                    eth_addr_dump(&chg_lst.addrs[i], mac, sizeof(mac)),
                    dev->name, dpvs_strerror(err));
            break;
        default:
            /* should not happen. */
            RTE_LOG(ERR, Kni, "%s: invalid state for mac: %s!\n", __func__,
                    eth_addr_dump(&chg_lst.addrs[i], mac, sizeof(mac)));
            err = EDPVS_INVAL;
            goto out;
        }
    }

    err = __netif_set_mc_list(dev);

out:
    rte_rwlock_write_unlock(&dev->dev_lock);
    return err;
}

static int kni_update_maddr(struct netif_port *dev)
{
    FILE *fp;
    char line[1024];
    int ifindex, users, st; /* @st for static */
    char ifname[IFNAMSIZ], hexa[256]; /* hex address */
    struct rte_ether_addr ma_list[NETIF_MAX_HWADDR];
    int n_ma;

    fp = fopen("/proc/net/dev_mcast", "r");
    if (!fp) {
        RTE_LOG(WARNING, Kni, "%s: fail to open proc file: %s.\n",
                __func__, strerror(errno));
        return EDPVS_SYSCALL;
    }

    RTE_LOG(DEBUG, Kni, "%s: set mcast to %s\n", __func__,
            rte_kni_get_name(dev->kni.kni));

    n_ma = 0;
    while (n_ma < NELEMS(ma_list) && fgets(line, sizeof(line), fp)) {
        unsigned int ma[6], i;

        if (sscanf(line, "%d%s%d%d%s", &ifindex, ifname, &users,
                   &st, hexa) != 5)
            continue;

        if (strcmp(ifname, rte_kni_get_name(dev->kni.kni)) != 0)
            continue;

        sscanf(hexa, "%02x%02x%02x%02x%02x%02x",
                &ma[0], &ma[1], &ma[2], &ma[3], &ma[4], &ma[5]);

        for (i = 0; i < NELEMS(ma); i++)
            ma_list[n_ma].addr_bytes[i] = (uint8_t)ma[i];

        n_ma++;
    }

    fclose(fp);

    /* note: n_ma == 0 is Ok (may means all deleted.) */

    /*
     * XXX: compare and config netif for addresses changed (add/del/...).
     * it's not ideal way but should we change kni driver to report what
     * hwaddrs are exactly changed ?
     */
    return kni_mc_list_cmp_set(dev, ma_list, n_ma);
}

static int kni_rtnl_check(void *arg)
{
    struct netif_port *dev = arg;
    int fd = dev->kni.kni_rtnl_fd;
    int n, i, link_flags = 0;
    char buf[4096];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    bool update = false;
    int max_trials = 1000;

    /* try to handle more events once, because we're not really
     * event-driven, the polling speed may not fast enough.
     * there may not so may events in real world ? but when
     * performan strength test, it's really found kni_rtnl_timer
     * is too slow, so that more and more events queued. */

    for (i = 0; i < max_trials; i++) {
        n = recv(fd, nlh, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                break; /* no more events */
            RTE_LOG(WARNING, Kni, "fail to check kni event!\n");
            return DTIMER_OK;
        } else if (n == 0)
            break; /* closed */

        while (NLMSG_OK(nlh, n) && (nlh->nlmsg_type != NLMSG_DONE)) {
            if (nlh->nlmsg_type == RTM_NEWADDR) {
                update = true;
                break; /* not need handle all messages, recv again. */
            }

            nlh = NLMSG_NEXT(nlh, n);
        }
    }

    if (!kni_dev_exist(dev))
        return DTIMER_OK;

    /* note we should not update kni mac list for every event ! */
    if (update) {
        RTE_LOG(DEBUG, Kni, "%d events received!\n", i);
        if (EDPVS_OK != linux_get_link_status(dev->kni.name, &link_flags, NULL, 0)) {
            RTE_LOG(ERR, Kni, "%s：undetermined kni link status\n", dev->kni.name);
            return DTIMER_OK;
        }
        if (!(link_flags & IFF_UP)) {
            RTE_LOG(DEBUG, Kni, "skip link down kni device %s\n", dev->kni.name);
            return DTIMER_OK;
        }
        if (kni_update_maddr(dev) == EDPVS_OK)
            RTE_LOG(DEBUG, Kni, "update maddr of %s OK!\n", dev->name);
        else
            RTE_LOG(ERR, Kni, "update maddr of %s Failed!\n", dev->name);
    }

    return DTIMER_OK;
}

static int kni_rtnl_init(struct netif_port *dev)
{
    struct sockaddr_nl snl;
    int sockfd = -1;
    int err = EDPVS_SYSCALL;
    struct timeval tv;

    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd < 0)
        goto errout;

    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    snl.nl_groups = RTMGRP_NOTIFY;

    if (bind(sockfd, (struct sockaddr *)&snl, sizeof(snl)) < 0)
        goto errout;

    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0)
        goto errout;

    dev->kni.kni_rtnl_fd = sockfd;

    /* no way to driven by event, we are in dpdk polling model.
     * to use netif-job ? no, it's for worker cores.
     * then have to use timer, event + polling, a bit strange. */
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    err = dpvs_timer_sched_period(&dev->kni.kni_rtnl_timer, &tv,
                                  kni_rtnl_check, dev, true);
    if (err != EDPVS_OK)
        goto errout;

    return EDPVS_OK;

errout:
    if (sockfd >= 0)
        close(sockfd);
    return err;
}

/*
 * @dev     - real device kni attach to.
 * @kniname - optional, kni device name or auto generate.
 */
int kni_add_dev(struct netif_port *dev, const char *kniname)
{
    struct rte_kni_conf conf;
    struct rte_kni *kni;
    int err;
    char ring_name[RTE_RING_NAMESIZE];
    struct rte_ring *rb;

    if (!g_kni_enabled)
        return EDPVS_OK;

    if (!dev)
        return EDPVS_INVAL;

    if (dev->type == PORT_TYPE_BOND_SLAVE)
        return EDPVS_NOTSUPP;

    if (kni_dev_exist(dev)) {
        RTE_LOG(ERR, Kni, "%s: dev %s has already attached with kni\n",
                __func__, dev->name);
        return EDPVS_EXIST;
    }

    kni_fill_conf(dev, kniname, &conf);

    kni = rte_kni_alloc(pktmbuf_pool[dev->socket], &conf, NULL);
    if (!kni)
        return EDPVS_DPDKAPIFAIL;

    err = kni_rtnl_init(dev);
    if (err != EDPVS_OK) {
        rte_kni_release(kni);
        return err;
    }

    snprintf(ring_name, sizeof(ring_name), "kni_rx_ring_%s",
             conf.name);
    rb = rte_ring_create(ring_name, KNI_RX_RING_ELEMS,
                         rte_socket_id(), RING_F_SC_DEQ);
    if (unlikely(!rb)) {
        RTE_LOG(ERR, KNI, "[%s] Failed to create kni rx ring.\n", __func__);
        rte_kni_release(kni);
        return EDPVS_DPDKAPIFAIL;
    }

    snprintf(dev->kni.name, sizeof(dev->kni.name), "%s", conf.name);
    dev->kni.addr = dev->addr;
    dev->kni.kni = kni;
    dev->kni.rx_ring = rb;
    INIT_LIST_HEAD(&dev->kni.kni_flows);
    return EDPVS_OK;
}

int kni_del_dev(struct netif_port *dev)
{
    if (!g_kni_enabled)
        return EDPVS_OK;

    if (!kni_dev_exist(dev))
        return EDPVS_INVAL;

    rte_kni_release(dev->kni.kni);
    rte_ring_free(dev->kni.rx_ring);
    dev->kni.kni = NULL;
    dev->kni.rx_ring = NULL;
    return EDPVS_OK;
}

/////////////// KNI FLOW //////////////

/*
 * Kni Address Flow:
 * The idea is to specify kni interface with an ip address, and isolate all traffic
 * target at the address to a dedicated nic rx-queue, which may avoid disturbances
 * of dataplane when overload.
 * Note that not all nic can support this flow type under the premise of sapool.
 * See `check_kni_addr_flow_support` for supported nics as we known so far. It's
 * encouraged to add more nic types satisfied the flow type.
 */

#define NETDEV_IXGBE_DRIVER_NAME      "ixgbe"
#define NETDEV_I40E_DRIVER_NAME       "i40e"
#define NETDEV_MLNX_DRIVER_NAME       "mlx5"

static bool check_kni_addr_flow_support(const struct netif_port *dev)
{
    if (dev->type == PORT_TYPE_BOND_MASTER) {
        int i;
        for (i = 0; i < dev->bond->master.slave_nb; i++) {
            if (!check_kni_addr_flow_support(dev->bond->master.slaves[i]))
                return false;
        }
        return true;
    } else if (dev->type == PORT_TYPE_VLAN) {
        const struct vlan_dev_priv *vlan = netif_priv_const(dev);
        assert(vlan && vlan->real_dev);
        return check_kni_addr_flow_support(vlan->real_dev);
    }

    // PMD drivers support kni address flow
    //  - mlx5
    //  - ixgbe
    //  - ...
    // PMD drivers do NOT support kni address flow
    //  - ...
    if (strstr(dev->dev_info.driver_name, NETDEV_MLNX_DRIVER_NAME))
        return true;
    if (strstr(dev->dev_info.driver_name, NETDEV_IXGBE_DRIVER_NAME))
        return true;

    // TODO：check and then add more supported types

    return false;
}

static inline int kni_addr_flow_allowed(const struct netif_port *dev)
{
    if (!g_kni_lcore_id)
        return EDPVS_DISABLED;

    if (dev->type != PORT_TYPE_GENERAL
            && dev->type != PORT_TYPE_VLAN
            && dev->type != PORT_TYPE_BOND_MASTER) {
        RTE_LOG(WARNING, KNI, "%s: kni addr flow only supports physical (exclusive"
                " of bonding slaves), vlan, and bonding master devices\n", __func__);
        return EDPVS_NOTSUPP;
    }

    if (!check_kni_addr_flow_support(dev)) {
        RTE_LOG(WARNING, KNI, "%s: %s (driver: %s) doesn't support kni address flow, steer kni "
                "traffic onto slave workers\n", __func__, dev->name, dev->dev_info.driver_name);
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static struct kni_addr_flow* kni_addr_flow_lookup(const struct netif_port *dev,
                             const struct kni_addr_flow_entry *param) {
    struct kni_addr_flow *flow;
    if (unlikely(!param || !dev))
        return NULL;

    list_for_each_entry(flow, &dev->kni.kni_flows, node) {
        if (flow->af == param->af &&
                inet_addr_equal(flow->af, &flow->addr, &param->addr))
            return flow;
    }
    return NULL;
}

static int kni_addr_flow_add(struct netif_port *dev, const struct kni_addr_flow_entry *param)
{
    int err;
    struct kni_addr_flow *flow;
    struct netif_flow_handler_param flow_handlers;

    if ((err = kni_addr_flow_allowed(dev)) != EDPVS_OK)
        return err;

    if (kni_addr_flow_lookup(dev, param))
        return EDPVS_EXIST;

    flow = rte_malloc("kni_addr_flow", sizeof(struct kni_addr_flow), RTE_CACHE_LINE_SIZE);
    if (unlikely(flow == NULL))
        return EDPVS_NOMEM;
    flow->af = param->af;
    flow->addr = param->addr;
    flow->dev = dev;
    flow->kni_worker = g_kni_lcore_id;

    flow_handlers.size = NELEMS(flow->flows),
    flow_handlers.flow_num = 0,
    flow_handlers.handlers = &flow->flows[0],
    err = netif_kni_flow_add(dev, flow->kni_worker, flow->af, &flow->addr, &flow_handlers);
    if (err != EDPVS_OK) {
        rte_free(flow);
        return err;
    }
    flow->nflows = flow_handlers.flow_num;

    list_add(&flow->node, &dev->kni.kni_flows);

    return EDPVS_OK;
}

static int kni_addr_flow_del(struct netif_port *dev, const struct kni_addr_flow_entry *param)
{
    int err;
    struct kni_addr_flow *flow;
    struct netif_flow_handler_param flow_handlers;

    if ((err = kni_addr_flow_allowed(dev)) != EDPVS_OK)
        return err;

    flow = kni_addr_flow_lookup(dev, param);
    if (!flow)
        return EDPVS_NOTEXIST;

    list_del(&flow->node);

    flow_handlers.size = NELEMS(flow->flows);
    flow_handlers.flow_num = flow->nflows;
    flow_handlers.handlers = &flow->flows[0];
    err = netif_kni_flow_del(dev, flow->kni_worker, flow->af, &flow->addr, &flow_handlers);
    if (err != EDPVS_OK) {
        list_add(&flow->node, &dev->kni.kni_flows);
        return err;
    }

    rte_free(flow);
    return EDPVS_OK;
}

static int kni_addr_flow_flush(struct netif_port *dev)
{
    int err, retval = EDPVS_OK;
    struct kni_addr_flow *flow, *next;
    struct netif_flow_handler_param flow_handlers;

    if ((err = kni_addr_flow_allowed(dev)) != EDPVS_OK)
        return err;

    list_for_each_entry_safe(flow, next, &dev->kni.kni_flows, node) {
        list_del(&flow->node);
        flow_handlers.size = NELEMS(flow->flows);
        flow_handlers.flow_num = flow->nflows;
        flow_handlers.handlers = &flow->flows[0];
        err = netif_kni_flow_del(dev, flow->kni_worker, flow->af, &flow->addr, &flow_handlers);
        if (err != EDPVS_OK) {
            retval = err;
            list_add(&flow->node, &dev->kni.kni_flows);
        } else {
            rte_free(flow);
        }
    }

    return retval;
}

static void inline kni_addr_flow_fill_entry(const struct kni_addr_flow *flow,
        struct kni_conf_param *entry) {
    snprintf(entry->ifname, sizeof(entry->ifname), "%s", flow->dev->name);
    entry->type = KNI_DTYPE_ADDR_FLOW;
    entry->data.flow.af = flow->af;
    entry->data.flow.addr = flow->addr;
}

static int kni_addr_flow_get(struct netif_port *dev, const struct kni_addr_flow_entry *param,
        struct kni_info **pentries, int *plen)
{
    int i, n, err;
    size_t memlen;
    struct kni_addr_flow *flow;
    struct kni_info *info;

    if ((err = kni_addr_flow_allowed(dev)) != EDPVS_OK)
        return err;

    i = 0;
    n = list_elems(&dev->kni.kni_flows);
    memlen = sizeof(struct kni_info) + n * sizeof(struct kni_conf_param);
    info = rte_calloc("kni_addr_flow_get", 1, memlen, RTE_CACHE_LINE_SIZE);
    if (unlikely(!info))
        return EDPVS_NOMEM;

    list_for_each_entry(flow, &dev->kni.kni_flows, node) {
        assert(i < n);
        kni_addr_flow_fill_entry(flow, &info->entries[i++]);
    }
    assert(i == n);
    info->len = n;

    *plen = memlen;
    *pentries = info;
    return EDPVS_OK;
}

/////////////// KNI FLOW END //////////////

static int kni_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct kni_conf_param *param = conf;
    struct netif_port *dev;

    if (!conf || size < sizeof(struct kni_conf_param))
        return EDPVS_INVAL;

    if (param->type != KNI_DTYPE_ADDR_FLOW)
        return EDPVS_NOTSUPP;

    dev = netif_port_get_by_name(param->ifname);
    if (!dev)
        return EDPVS_NOTEXIST;

    switch (opt) {
        case SOCKOPT_SET_KNI_ADD:
            return kni_addr_flow_add(dev, &param->data.flow);
        case SOCKOPT_SET_KNI_DEL:
            return kni_addr_flow_del(dev, &param->data.flow);
        case SOCKOPT_SET_KNI_FLUSH:
            return kni_addr_flow_flush(dev);
        default:
            return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static int kni_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                        void **out, size_t *outsize)
{
    int err, len = 0;
    struct netif_port *dev;
    struct kni_info *info = NULL;
    const struct kni_conf_param *param = conf;

    if (!conf || size < sizeof(struct kni_conf_param) || !out || !outsize)
        return EDPVS_INVAL;

    if (opt != SOCKOPT_GET_KNI_LIST)
        return EDPVS_NOTSUPP;

    if (param->type != KNI_DTYPE_ADDR_FLOW)
        return EDPVS_NOTSUPP;

    dev = netif_port_get_by_name(param->ifname);
    if (!dev)
        return EDPVS_NOTEXIST;

    err = kni_addr_flow_get(dev, &param->data.flow, &info, &len);
    if (err != EDPVS_OK)
        return err;

    *out = info;
    *outsize = len;
    return EDPVS_OK;
}

static struct dpvs_sockopts kni_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_KNI_ADD,
    .set_opt_max    = SOCKOPT_SET_KNI_FLUSH,
    .set            = kni_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_KNI_LIST,
    .get_opt_max    = SOCKOPT_GET_KNI_LIST,
    .get            = kni_sockopt_get,
};

int kni_init(void)
{
    if (!g_kni_enabled)
        return EDPVS_OK;

    if (rte_kni_init(NETIF_MAX_KNI) < 0)
        rte_exit(EXIT_FAILURE, "rte_kni_init failed");

    return EDPVS_OK;
}

int kni_ctrl_init(void)
{
    int err;

    if (!g_kni_enabled)
        return EDPVS_OK;

    err = sockopt_register(&kni_sockopts);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, KNI, "%s: fail to register kni_sockopts -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    return EDPVS_OK;
}

int kni_ctrl_term(void)
{
    int err;

    if (!g_kni_enabled)
        return EDPVS_OK;

    err = sockopt_unregister(&kni_sockopts);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, KNI, "%s: fail to unregister kni_sockopts -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    return EDPVS_OK;
}
