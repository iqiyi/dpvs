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
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <linux/sockios.h>
#include "linux_if.h"
#include "conf/common.h"

int linux_get_link_status(const char *ifname, int *if_flags, char *if_flags_str, size_t len)
{
    int sock_fd;
    struct ifreq ifr = {};

    if (!ifname || !if_flags)
        return EDPVS_INVAL;

    *if_flags= 0;

    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
        return EDPVS_SYSCALL;

    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr)) {
        fprintf(stderr, "%s: fail to get %s's flags -- %s\n",
                __func__, ifname, strerror(errno));
        close(sock_fd);
        return EDPVS_IO;
    }
    close(sock_fd);

    *if_flags = ifr.ifr_flags;

    if (if_flags_str) {
        int idx = 0;
        idx += snprintf(&if_flags_str[idx], len-idx-1, "%s:", ifname);
        if(*if_flags & IFF_UP)
            idx += snprintf(&if_flags_str[idx], len-idx-1, " UP");
        if(*if_flags & IFF_MULTICAST)
           idx += snprintf(&if_flags_str[idx], len-idx-1, " MULTICAST");
        if(*if_flags & IFF_BROADCAST)
            idx += snprintf(&if_flags_str[idx], len-idx-1, " BROADCAST");
        if(*if_flags & IFF_LOOPBACK)
            idx += snprintf(&if_flags_str[idx], len-idx-1, " LOOPBACK");
        if(*if_flags & IFF_POINTOPOINT)
            idx += snprintf(&if_flags_str[idx], len-idx-1, " P2P");
    }

    return EDPVS_OK;
}

int linux_set_if_mac(const char *ifname, const unsigned char mac[ETH_ALEN])
{
    int err;
    int sock_fd, if_flags;
    struct ifreq ifr = {};

    if (!ifname || !mac || !strncmp(ifname, "lo", 2))
        return EDPVS_INVAL;

    err = linux_get_link_status(ifname, &if_flags, NULL, 0);
    if (err != EDPVS_OK)
        return err;

    if (!(if_flags & IFF_UP)) {
        fprintf(stderr, "%s: skip MAC address update of link down device %s\n",
                __func__, ifname);
        return EDPVS_RESOURCE;
    }

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
        return EDPVS_SYSCALL;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ifr.ifr_hwaddr.sa_family = 1;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, ETH_ALEN);

    if (ioctl(sock_fd, SIOCSIFHWADDR, &ifr)) {
        fprintf(stderr, "%s: fail to set %s's MAC address -- %s\n",
                __func__, ifname, strerror(errno));
        close(sock_fd);
        return EDPVS_IO;
    }
    close(sock_fd);

    return EDPVS_OK;
}

static int linux_hw_mc_mod(const char *ifname,
                           const uint8_t hwma[ETH_ALEN], bool add)
{
    int fd, cmd;
    struct ifreq ifr = {};

    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    memcpy(&ifr.ifr_hwaddr.sa_data, hwma, ETH_ALEN);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return EDPVS_SYSCALL;

    cmd = add ? SIOCADDMULTI : SIOCDELMULTI;
    if (ioctl(fd, cmd, (void *)&ifr) != 0) {
        fprintf(stderr, "%s: fail to set link mcast to %s: %s\n",
                __func__, ifname, strerror(errno));
        close(fd);
        /* Ignore the error because 'kni_net_process_request' may get timeout. */
        return EDPVS_OK;
    }

    close(fd);
    return EDPVS_OK;
}

int linux_hw_mc_add(const char *ifname, const uint8_t hwma[ETH_ALEN])
{
    return linux_hw_mc_mod(ifname, hwma, true);
}

int linux_hw_mc_del(const char *ifname, const uint8_t hwma[ETH_ALEN])
{
    return linux_hw_mc_mod(ifname, hwma, false);
}

int linux_ifname2index(const char *ifname)
{
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -1;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        close(sockfd);
        return -1;
    }
    close(sockfd);

    return ifr.ifr_ifindex;
}

int linux_get_tx_csum_offload(const char *ifname)
{
    int sockfd;
    struct ifreq ifr;
    struct ethtool_value edata;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -1;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    edata.cmd = ETHTOOL_GTXCSUM;
    ifr.ifr_data = (caddr_t)&edata;
    if (ioctl(sockfd, SIOCETHTOOL, &ifr) == -1) {
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return edata.data;
}

int linux_set_tx_csum_offload(const char *ifname, int on)
{
    int sockfd;
    struct ifreq ifr;
    struct ethtool_value edata;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -1;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    edata.cmd = ETHTOOL_STXCSUM;
    edata.data = on ? 1 : 0;
    ifr.ifr_data = (caddr_t)&edata;

    if (ioctl(sockfd, SIOCETHTOOL, &ifr) == -1) {
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

// Get offload features for a linux device.
// Param `gfeatures` must be allocated with memory at least of `nblocks` blocks.
// Feature definitions refer to linux kernel header: include/linux/netdev_features.h.
int linux_get_if_features(const char *ifname, int nblocks, struct ethtool_gfeatures *gfeatures)
{
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return -1;

    gfeatures->cmd = ETHTOOL_GFEATURES;
    gfeatures->size = nblocks;
    memset(gfeatures->features, 0, gfeatures->size * sizeof(gfeatures->features[0]));

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_data = (caddr_t)gfeatures;

    if (ioctl(sockfd, SIOCETHTOOL, &ifr) == -1) {
        close(sockfd);
        return -1;
    }

    return 0;
}
