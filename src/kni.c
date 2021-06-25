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
#include "netif_addr.h"
#include "netdev_flow.h"
#include "kni.h"

#define Kni /* KNI is defined */
#define RTE_LOGTYPE_Kni     RTE_LOGTYPE_USER1

#define KNI_DEF_MBUF_SIZE       2048
#define KNI_MBUFPOOL_ELEMS      65535
#define KNI_MBUFPOOL_CACHE_SIZE 256

static struct rte_mempool *kni_mbuf_pool[DPVS_MAX_SOCKET];

extern netif_filter_op_func g_netif_filter_func;

/* kni fdir info */
static struct kni_fdir kni_fdir = { .init_success = false, .port_base_num = 0 };

static void kni_fill_conf(const struct netif_port *dev, const char *ifname,
                          struct rte_kni_conf *conf)
{
    struct rte_eth_dev_info info = {0};

    memset(conf, 0, sizeof(*conf));
    conf->group_id = dev->id;
    conf->mbuf_size = KNI_DEF_MBUF_SIZE;

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
                               struct ether_addr *addrs, size_t naddr)
{
    int err = EDPVS_INVAL, i, j;
    struct ether_addr addrs_old[NETIF_MAX_HWADDR];
    size_t naddr_old;
    char mac[64];
    struct mc_change_list {
        size_t              naddr;
        struct ether_addr   addrs[NETIF_MAX_HWADDR*2];
        /* state: 0 - unchanged, 1 - added, 2 deleted. */
        int                 states[NETIF_MAX_HWADDR*2];
    } chg_lst = {0};

    rte_rwlock_write_lock(&dev->dev_lock);

    naddr_old = NELEMS(addrs_old);
    err = __netif_mc_dump(dev, addrs_old, &naddr_old);
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
        ether_addr_copy(&addrs[i], &chg_lst.addrs[i]);
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

            ether_addr_copy(&addrs_old[i], &chg_lst.addrs[chg_lst.naddr]);
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
            err = __netif_mc_add(dev, &chg_lst.addrs[i]);

            RTE_LOG(INFO, Kni, "%s: add mc addr: %s %s %s\n", __func__,
                    eth_addr_dump(&chg_lst.addrs[i], mac, sizeof(mac)),
                    dev->name, dpvs_strerror(err));
            break;
        case 2:
            err = __netif_mc_del(dev, &chg_lst.addrs[i]);

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
    struct ether_addr ma_list[NETIF_MAX_HWADDR];
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
    int n, i;
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

    kni = rte_kni_alloc(kni_mbuf_pool[dev->socket], &conf, NULL);
    if (!kni)
        return EDPVS_DPDKAPIFAIL;

    err = kni_rtnl_init(dev);
    if (err != EDPVS_OK) {
        rte_kni_release(kni);
        return err;
    }

    /*
     * kni device should use same mac as real device,
     * because it may config same IP of real device.
     * diff mac means kni cannot accept packets sent
     * to real-device.
     */
    err = linux_set_if_mac(conf.name, (unsigned char *)&dev->addr);
    if (err != EDPVS_OK) {
        char mac[18];
        ether_format_addr(mac, sizeof(mac), &dev->addr);
        RTE_LOG(WARNING, Kni, "%s: fail to set mac %s for %s: %s\n",
                __func__, mac, conf.name, strerror(errno));
    }

    snprintf(ring_name, sizeof(ring_name), "kni_rx_ring_%s",
             conf.name);
    rb = rte_ring_create(ring_name, KNI_DEF_MBUF_SIZE,
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
    return EDPVS_OK;
}

int kni_del_dev(struct netif_port *dev)
{
    if (!kni_dev_exist(dev))
        return EDPVS_INVAL;

    rte_kni_release(dev->kni.kni);
    rte_ring_free(dev->kni.rx_ring);
    dev->kni.kni = NULL;
    dev->kni.rx_ring = NULL;
    return EDPVS_OK;
}

/*
 * @brief: init kni fdir, set dip + proto + dport + dst_port_mask
 *         filters for kni_ip to replace dip + proto filter
 *
 * @return EDPVS_OK on success, EDPVS_INVAL on failure
 */
int kni_fdir_init(void)
{
    int i, shift;
    uint16_t port_base;
    uint8_t total_nlcore;
    uint8_t expected_nlcore;
    uint64_t total_lcore_mask;

    /* get total lcore mask, including worker only */
    netif_get_slave_lcores(&total_nlcore, &total_lcore_mask);

    RTE_LOG(INFO, Kni, "[%s] total_nlcore: %d total_lcore_mask: %llx\n",
            __func__, total_nlcore, total_lcore_mask);

    for (shift = 0; (0x1 << shift) < total_nlcore; shift++)
        ;
    /* exceed maxnum lcore num */
    if (shift >= 16) {
        RTE_LOG(ERR, Kni, "[%s] invalid shift: %d total_nlcore: %d\n",
                __func__, shift, total_nlcore);
        return EDPVS_INVAL;
    }

    port_base = 0;
    expected_nlcore = (0x1 << shift);
    kni_fdir.filter_mask = ~((~0x0) << shift);

    /* specify the num of filters to cover port range [0-65535] */
    for (i = 0; i < expected_nlcore; i++) {
        kni_fdir.port_base_array[kni_fdir.port_base_num] = htons(port_base);
        memset(kni_fdir.soft_id_array[kni_fdir.port_base_num], 0, MAX_FDIR_PROTO);
        RTE_LOG(INFO, Kni, "[%s] port_base_array[%d]: %d\n",
                __func__, kni_fdir.port_base_num, htons(port_base));
        kni_fdir.port_base_num++;
        port_base++;
    }

    RTE_LOG(INFO, Kni, "[%s] kni fdir init success, port_base_num: %d\n",
            __func__, kni_fdir.port_base_num);

    /* set kni fdir init flag */
    kni_fdir.init_success = true;

    return EDPVS_OK;
}

/*
 * @brief: add kni fdir, set high priority for bgp/hc
 *         which will be redirected to kni core on hardware
 *
 * @param af - AF_INET or AF_INET6 on kni ip
 * @param dev - lan or wan link to add kni fdir
 * @param kni_ip - kni ip address
 *
 * @return EDPVS_OK on success, negative on failure
 */
int kni_fdir_filter_add(struct netif_port *dev,
                        const union inet_addr *kni_ip,
                        int af)
{
    int err = EDPVS_OK;
    int i = 0;
    char dst[64];
    union inet_addr addr;
    lcoreid_t kni_lcore_id = netif_get_kni_lcore_id();

    /* params assert */
    if (unlikely(dev == NULL || kni_ip == NULL
        || kni_lcore_id == 0)) {
        RTE_LOG(ERR, Kni, "[%s] invalid kni fdir params info on port\n", __func__);
        return EDPVS_INVAL;
    }

    if (unlikely(!kni_fdir.init_success || kni_fdir.port_base_num == 0
        || g_netif_filter_func == NULL)) {
        RTE_LOG(ERR, Kni, "[%s] kni fdir info uninitialized on port\n", __func__);
        return EDPVS_INVAL;
    }

    /* signature mode is required for ipv6 filter on ixgbe */
    if (af == AF_INET6
        && dev->dev_conf.fdir_conf.mode != RTE_FDIR_MODE_SIGNATURE
        && strstr(dev->dev_info.driver_name, NETDEV_IXGBE_DRIVER_NAME) != NULL) {
        RTE_LOG(ERR, Kni, "[%s] kni ipv6 fdir filter require signature mode on ixgbe\n", __func__);
        return EDPVS_INVAL;
    }

    for (i = 0; i < kni_fdir.port_base_num; i++) {
        err = g_netif_filter_func(af, dev,
                                  kni_lcore_id, kni_ip,
                                  kni_fdir.port_base_array[i],
                                  kni_fdir.soft_id_array[i],
                                  true);
        if (unlikely(err != EDPVS_OK)) {
            RTE_LOG(ERR, Kni, "[%s] fail to add kni fdir %s filter "
                    "on port: %s for port_base: %d\n",
                    __func__, af == AF_INET ? "ipv4" : "ipv6",
                    dev->name, kni_fdir.port_base_array[i]);
            return EDPVS_NOTSUPP;
        }
    }

    if (af == AF_INET) {
        addr.in.s_addr = kni_ip->in.s_addr;
        RTE_LOG(INFO, Kni, "[%s] success to add kni fdir ipv4 filter "
                "on port: %s for kni_ip: %s\n",
                __func__, dev->name,
                inet_ntop(AF_INET, &addr, dst, sizeof(dst)) ? dst: "");
    } else {
        inet_ntop(AF_INET6, kni_ip, dst, sizeof(dst));
        RTE_LOG(INFO, Kni, "[%s] success to add kni fdir ipv6 filter "
                "on port: %s for kni_ip: %s\n",
                __func__, dev->name, dst);
    }

    return EDPVS_OK;
}

int kni_init(void)
{
    int i;
    char poolname[32];

    for (i = 0; i < get_numa_nodes(); i++) {
        memset(poolname, 0, sizeof(poolname));
        snprintf(poolname, sizeof(poolname) - 1, "kni_mbuf_pool_%d", i);

        kni_mbuf_pool[i] = rte_pktmbuf_pool_create(poolname, KNI_MBUFPOOL_ELEMS,
                KNI_MBUFPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, i);
        if (!kni_mbuf_pool[i])
            rte_exit(EXIT_FAILURE, "Fail to create pktmbuf_pool for kni.");
    }

    return EDPVS_OK;
}
