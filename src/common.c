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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <numa.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include "conf/common.h"

struct dpvs_err_tab {
    int errcode;
    const char *errmsg;
};

const char *dpvs_strerror(int err)
{
    /* TODO: "per-lcorelize" it */
    const static struct dpvs_err_tab err_tab[] = {
        { EDPVS_OK,             "OK" },
        { EDPVS_INVAL,          "invalid parameter" },
        { EDPVS_NOMEM,          "no memory" },
        { EDPVS_EXIST,          "already exist" },
        { EDPVS_NOTEXIST,       "not exist" },
        { EDPVS_INVPKT,         "invalid packet" },
        { EDPVS_DROP,           "packet dropped" },
        { EDPVS_NOPROT,         "no protocol" },
        { EDPVS_NOROUTE,        "no route" },
        { EDPVS_DEFRAG,         "defragment error" },
        { EDPVS_FRAG,           "fragment error" },
        { EDPVS_DPDKAPIFAIL,    "failed dpdk api" },
        { EDPVS_IDLE,           "nothing to do" },
        { EDPVS_BUSY,           "resource busy" },
        { EDPVS_NOTSUPP,        "not support" },
        { EDPVS_RESOURCE,       "no resource" },
        { EDPVS_OVERLOAD,       "overloaded" },
        { EDPVS_NOSERV,         "no service" },
        { EDPVS_DISABLED,       "disabled" },
        { EDPVS_NOROOM,         "no room" },
        { EDPVS_NONEALCORE,     "non-EAL thread lcore" },
        { EDPVS_CALLBACKFAIL,   "callback failed" },
        { EDPVS_IO,             "I/O error" },
        { EDPVS_MSG_FAIL,       "msg callback failed"},
        { EDPVS_MSG_DROP,       "msg dropped"},
        { EDPVS_PKTSTOLEN,      "stolen packet"},
        { EDPVS_SYSCALL,        "system call failed"},
        { EDPVS_NODEV,          "no such device"},

        { EDPVS_KNICONTINUE,    "kni to continue"},
        { EDPVS_INPROGRESS,     "in progress"},
    };
    int i;

    for (i = 0; i < NELEMS(err_tab); i++) {
        if (err == err_tab[i].errcode)
            return err_tab[i].errmsg;
    }

    return "<unknow>";
}

static dpvs_state_t g_dpvs_tate = DPVS_STATE_STOP;

void dpvs_state_set(dpvs_state_t stat)
{
    g_dpvs_tate = stat;
}

dpvs_state_t dpvs_state_get(void)
{
    return g_dpvs_tate;
}

int get_numa_nodes(void)
{
    int numa_nodes;

    if (numa_available() < 0)
        numa_nodes = 0;
    else
        numa_nodes = numa_max_node();

    return (numa_nodes + 1);
}

/* if (num+offset) == 2^n, return true,
 * otherwise return false and 'lower' is filled with
 * the closest lower bound value to 'num' */
bool is_power2(int num, int offset, int *lower)
{
    int i, onum;
    bool ret = true;

    onum = num + offset;
    if (num < 2 || onum < 2) {
        if (lower)
            *lower = num;
        return false;
    }

    for (i = 1; (onum >> i) > 1;i++) {
        if ((onum >> i) % 2) {
            ret = false;
        }
    }

    if (lower)
        *lower = (1u << i);
    return ret;
}

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

    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
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

ssize_t readn(int fd, void *vptr, size_t n)
{
    size_t nleft;
    ssize_t nread;
    char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ((nread = read(fd, ptr, nleft)) < 0) {
            if (errno == EINTR)
                nread = 0;      /* and call read() again */
            else
                return (-1);
        } else if (nread == 0)
            break;      /* EOF */

        nleft -= nread;
        ptr += nread;
    }

    return (n - nleft);     /* return >= 0 */
}

/* write "n" bytes to a descriptor */
ssize_t writen(int fd, const void *vptr, size_t n)
{
    size_t nleft;
    ssize_t nwritten;
    const char *ptr;

    ptr = vptr;
    nleft = n;

    while (nleft > 0) {
        if ((nwritten = write(fd, ptr, nleft)) <= 0) {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0;       /* and call write() again */
            else
                return (-1);        /* error */
        }

        nleft -= nwritten;
        ptr += nwritten;
    }

    return (n);
}

/* send "n" bytes to a descriptor */
ssize_t sendn(int fd, const void *vptr, size_t n, int flags)
{
    size_t nleft;
    ssize_t nwritten;
    const char *ptr;

    ptr = vptr;
    nleft = n;

    while (nleft > 0) {
        if ((nwritten = send(fd, ptr, nleft, flags)) <= 0) {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0;       /* and call send() again */
            else
                return (-1);        /* error */
        }

        nleft -= nwritten;
        ptr += nwritten;
    }

    return (n);
}

