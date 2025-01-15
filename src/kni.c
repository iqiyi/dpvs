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
#include "netif.h"
#include "conf/netif_addr.h"
#include "ctrl.h"
#include "kni.h"
#include "vlan.h"
#include "conf/kni.h"
#include "conf/sockopts.h"

#define Kni /* KNI is defined */

#define KNI_RX_RING_ELEMS       2048
bool g_kni_enabled = true;


#ifdef CONFIG_KNI_VIRTIO_USER

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// TODO: let the params configurable
static uint16_t virtio_queues = 1;
static int virtio_queue_size = 1024;
static char vhost_dev_path[PATH_MAX] = "/dev/vhost-net";

static inline const char *kni_get_name(const struct netif_kni *kni)
{
    return kni->kni->ifname;
}

static struct virtio_kni* virtio_kni_alloc(struct netif_port *dev, const char *ifname)
{
    int err;
    portid_t pid;
    struct virtio_kni *kni = NULL;
    char portargs[1024];
    char portname[RTE_ETH_NAME_MAX_LEN];

    kni = rte_zmalloc("virtio_kni", sizeof(*kni), RTE_CACHE_LINE_SIZE);
    if (unlikely(!kni))
        return NULL;

    kni->master = dev;
    kni->queues = virtio_queues;
    kni->queue_size = virtio_queue_size;
    kni->path = rte_malloc("virtio_kni", strlen(vhost_dev_path) + 1, RTE_CACHE_LINE_SIZE);
    if (unlikely(!kni->path))
        goto errout;
    strcpy(kni->path, vhost_dev_path);
    err = snprintf(kni->dpdk_portname, sizeof(kni->dpdk_portname), "virtio_user%u", dev->id);
    if (unlikely(err > sizeof(kni->dpdk_portname))) {
        RTE_LOG(ERR, Kni, "%s: no enough room for dpdk_portname, expect %d\n", __func__, err);
        goto errout;
    }
    if (ifname)
        strncpy(kni->ifname, ifname, sizeof(kni->ifname) - 1);
    else
        snprintf(kni->ifname, sizeof(kni->ifname), "%s.kni", dev->name);

    // Refer to drivers/net/virtio/virtio_user_ethdev.c:virtio_user_driver for all supported args.
    // FIXME: Arg `speed` has no effects so that the virtio_kni port speed is always 10Mbps.
    err = snprintf(portargs, sizeof(portargs), "path=%s,queues=%u,queue_size=%u,iface=%s,"
            "speed=10000,mac=" RTE_ETHER_ADDR_PRT_FMT, kni->path, kni->queues, kni->queue_size,
            kni->ifname, RTE_ETHER_ADDR_BYTES(&dev->addr));
    if (unlikely(err > sizeof(portargs))) {
        RTE_LOG(ERR, Kni, "%s: no enough room for portargs, expect %d\n", __func__, err);
        goto errout;
    }

    err = rte_eal_hotplug_add("vdev", kni->dpdk_portname, portargs);
    if (err < 0) {
        RTE_LOG(ERR, Kni, "%s: virtio_kni hotplug_add failed: %d\n", __func__, err);
        goto errout;
    }

    RTE_ETH_FOREACH_DEV(pid) {
        rte_eth_dev_get_name_by_port(pid, portname);
        if (!strncmp(portname, kni->dpdk_portname, sizeof(kni->dpdk_portname))) {
            kni->dpdk_pid = pid;
            RTE_LOG(INFO, Kni, "%s: virtio_kni allocation succeed: ifname=%s, dpdk port %s, "
                    "id %d\n", __func__, kni->ifname, kni->dpdk_portname, pid);
            return kni;
        }
    }
    RTE_LOG(ERR, Kni, "%s: virtio_kni port id not found: ifname=%s, dpdk portname=%s\n",
            __func__, kni->ifname, kni->dpdk_portname);

errout:
    if (kni->path)
        rte_free(kni->path);
    if (kni)
        rte_free(kni);
    return NULL;
}

static void virtio_kni_free(struct virtio_kni **pkni)
{
    int err;
    struct virtio_kni *kni = *pkni;

    err = rte_eal_hotplug_remove("vdev", kni->dpdk_portname);
    if (err < 0)
        RTE_LOG(WARNING, Kni, "%s: virtio_kni hotplug_remove failed: %d\n", __func__, err);

    rte_free(kni->path);
    rte_free(kni);

    *pkni = NULL;
}

static struct rte_eth_conf virtio_kni_eth_conf = {
    .rxmode = {
        .mq_mode    = RTE_ETH_MQ_RX_NONE,
        .mtu        = RTE_ETHER_MTU,
        //.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_TCP_LRO,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
    .txmode = {
        .mq_mode    = RTE_ETH_MQ_TX_NONE,
        .offloads   = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE
                        | RTE_ETH_TX_OFFLOAD_TCP_TSO | RTE_ETH_TX_OFFLOAD_UDP_TSO
                        | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM
                        | RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_SCTP_CKSUM,
    },
};

static int virtio_kni_start(struct virtio_kni *kni)
{
    uint16_t q;
    int err;
    struct rte_eth_dev_info dev_info;
    struct rte_ether_addr macaddr;
    char strmac1[32], strmac2[32];

    rte_memcpy(&kni->eth_conf, &virtio_kni_eth_conf, sizeof(kni->eth_conf));

    err = rte_eth_dev_info_get(kni->dpdk_pid, &dev_info);
    if (err == EDPVS_OK) {
        kni->eth_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
        kni->eth_conf.rxmode.offloads &= dev_info.rx_offload_capa;
        kni->eth_conf.txmode.offloads &= dev_info.tx_offload_capa;
    } else {
        RTE_LOG(WARNING, Kni, "%s: rte_eth_dev_info_get(%s) failed: %d\n", __func__,
                kni->ifname, err);
    }

    err = rte_eth_dev_configure(kni->dpdk_pid, kni->queues, kni->queues, &kni->eth_conf);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: failed to config %s: %d\n", __func__, kni->ifname, err);
        return EDPVS_DPDKAPIFAIL;
    }

    for (q = 0; q < kni->queues; q++) {
        err = rte_eth_rx_queue_setup(kni->dpdk_pid, q, kni->queue_size,
                kni->master->socket, NULL, pktmbuf_pool[kni->master->socket]);
        if (err != EDPVS_OK) {
            RTE_LOG(ERR, Kni, "%s: failed to configure %s's queue %u: %d\n", __func__,
                    kni->ifname, q, err);
            return EDPVS_DPDKAPIFAIL;
        }
    }

    for (q = 0; q < kni->queues; q++) {
        err = rte_eth_tx_queue_setup(kni->dpdk_pid, q, kni->queue_size, kni->master->socket, NULL);
        if (err != EDPVS_OK) {
            RTE_LOG(ERR, Kni, "%s: failed to configure %s's queue %u: %d\n", __func__,
                    kni->ifname, q, err);
            return EDPVS_DPDKAPIFAIL;
        }
    }

    err = rte_eth_dev_start(kni->dpdk_pid);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: failed to start %s: %d\n", __func__, kni->ifname, err);
        return EDPVS_DPDKAPIFAIL;
    }

    //disable_kni_tx_csum_offload(kni->ifname);

    rte_eth_macaddr_get(kni->dpdk_pid, &macaddr);
    if (!eth_addr_equal(&macaddr, &kni->master->kni.addr)) {
        RTE_LOG(INFO, Kni, "%s: update %s mac addr: %s->%s\n", __func__, kni->ifname,
                eth_addr_dump(&kni->master->kni.addr, strmac1, sizeof(strmac1)),
                eth_addr_dump(&macaddr, strmac2, sizeof(strmac2)));
        kni->master->kni.addr = macaddr;
    }

    RTE_LOG(INFO, Kni, "%s: %s started success\n", __func__, kni->ifname);
    return EDPVS_OK;
}

static int virtio_kni_stop(struct virtio_kni *kni)
{
    int err;

    err = rte_eth_dev_stop(kni->dpdk_pid);
    if (err != EDPVS_OK) {
        if (err == EBUSY) {
            RTE_LOG(WARNING, Kni, "%s: %s is busy, retry later ...\n", __func__, kni->ifname);
            return EDPVS_BUSY;
        }
        RTE_LOG(ERR, Kni, "%s: failed to stop %s: %d\n", __func__, kni->ifname, err);
    }

    err = rte_eth_dev_close(kni->dpdk_pid);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: failed to close %s: %d\n", __func__, kni->ifname, err);
        return EDPVS_DPDKAPIFAIL;
    }

    RTE_LOG(INFO, Kni, "%s: %s stopped success\n", __func__, kni->ifname);
    return EDPVS_OK;
}

#else // !CONFIG_KNI_VIRTIO_USER
static inline const char *kni_get_name(const struct netif_kni *kni)
{
    return rte_kni_get_name(kni->kni);
}

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
#endif // CONFIG_KNI_VIRTIO_USER

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

    RTE_LOG(DEBUG, Kni, "%s: set mcast for %s\n", __func__, kni_get_name(&dev->kni));

    n_ma = 0;
    while (n_ma < NELEMS(ma_list) && fgets(line, sizeof(line), fp)) {
        unsigned int ma[6], i;

        if (sscanf(line, "%d%s%d%d%s", &ifindex, ifname, &users,
                   &st, hexa) != 5)
            continue;

        if (strcmp(ifname, kni_get_name(&dev->kni)) != 0)
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
            if (nlh->nlmsg_type == RTM_NEWADDR
#ifdef CONFIG_KNI_VIRTIO_USER
                    // FIXME: How to support layer2 only maddress changes?
                    || nlh->nlmsg_type == RTM_DELADDR
                    || nlh->nlmsg_type == RTM_NEWLINK
                    || nlh->nlmsg_type == RTM_DELLINK
#endif
                    ) {
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
#ifdef CONFIG_KNI_VIRTIO_USER
    snl.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
#else
    snl.nl_groups = RTMGRP_NOTIFY;
#endif

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
    int err;
    struct rte_ring *rb;
#ifdef CONFIG_KNI_VIRTIO_USER
    struct virtio_kni *kni;
#else
    struct rte_kni *kni;
    struct rte_kni_conf conf;
#endif
    char ring_name[RTE_RING_NAMESIZE];

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

#ifdef CONFIG_KNI_VIRTIO_USER
    kni = virtio_kni_alloc(dev, kniname);
    if (!kni)
        return EDPVS_RESOURCE;
#else
    kni_fill_conf(dev, kniname, &conf);
    kni = rte_kni_alloc(pktmbuf_pool[dev->socket], &conf, NULL);
    if (!kni)
        return EDPVS_DPDKAPIFAIL;
#endif

    err = kni_rtnl_init(dev);
    if (err != EDPVS_OK) {
#ifdef CONFIG_KNI_VIRTIO_USER
        virtio_kni_free(&kni);
#else
        rte_kni_release(kni);
#endif
        return err;
    }

#ifdef CONFIG_KNI_VIRTIO_USER
    snprintf(ring_name, sizeof(ring_name), "kni_rx_ring_%s", kni->ifname);
#else
    snprintf(ring_name, sizeof(ring_name), "kni_rx_ring_%s", conf.name);
#endif
    rb = rte_ring_create(ring_name, KNI_RX_RING_ELEMS,
                         rte_socket_id(), RING_F_SC_DEQ);
    if (unlikely(!rb)) {
        RTE_LOG(ERR, Kni, "%s: failed to create kni rx ring\n", __func__);
#ifdef CONFIG_KNI_VIRTIO_USER
        virtio_kni_free(&dev->kni.kni);
#else
        rte_kni_release(kni);
#endif
        return EDPVS_DPDKAPIFAIL;
    }

#ifdef CONFIG_KNI_VIRTIO_USER
    if ((err = virtio_kni_start(kni)) != EDPVS_OK) {
        rte_ring_free(dev->kni.rx_ring);
        dev->kni.rx_ring = NULL;
        virtio_kni_free(&dev->kni.kni);
        return err;
    }
#endif

    INIT_LIST_HEAD(&dev->kni.kni_flows);
    dev->kni.addr = dev->addr;
    dev->kni.rx_ring = rb;
    dev->kni.kni = kni;
    snprintf(dev->kni.name, sizeof(dev->kni.name), "%s", kni_get_name(&dev->kni));

    dev->kni.flags |= NETIF_PORT_FLAG_RUNNING;
    return EDPVS_OK;
}

int kni_del_dev(struct netif_port *dev)
{
    int err;

    if (!g_kni_enabled)
        return EDPVS_OK;

    if (!kni_dev_exist(dev))
        return EDPVS_INVAL;

    dev->kni.flags &= ~((uint16_t)NETIF_PORT_FLAG_RUNNING);

#ifdef CONFIG_KNI_VIRTIO_USER
    err = virtio_kni_stop(dev->kni.kni);
    if (err != EDPVS_OK) {
        // FIXME: retry when err is EDPVS_BUSY
        RTE_LOG(ERR, Kni, "%s: failed to stop virtio kni %s: %d\n", __func__, dev->kni.name, err);
        return err;
    }
    virtio_kni_free(&dev->kni.kni);
#else
    err = rte_kni_release(dev->kni.kni);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: failed to release kni %s: %d\n", __func__, dev->kni.name, err);
        return err;
    }
#endif

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
        RTE_LOG(WARNING, Kni, "%s: kni addr flow only supports physical (exclusive"
                " of bonding slaves), vlan, and bonding master devices\n", __func__);
        return EDPVS_NOTSUPP;
    }

    if (!check_kni_addr_flow_support(dev)) {
        RTE_LOG(WARNING, Kni, "%s: %s (driver: %s) doesn't support kni address flow, steer kni "
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

#ifndef CONFIG_KNI_VIRTIO_USER
    if (rte_kni_init(NETIF_MAX_KNI) < 0)
        rte_exit(EXIT_FAILURE, "rte_kni_init failed");
#endif

    return EDPVS_OK;
}

int kni_ctrl_init(void)
{
    int err;

    if (!g_kni_enabled)
        return EDPVS_OK;

    err = sockopt_register(&kni_sockopts);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: fail to register kni_sockopts -- %s\n",
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
        RTE_LOG(ERR, Kni, "%s: fail to unregister kni_sockopts -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    return EDPVS_OK;
}
