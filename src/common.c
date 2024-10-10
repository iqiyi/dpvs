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
#include <ifaddrs.h>
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

static uint8_t hex_char2num(char hex)
{
    if (hex >= '0' && hex <= '9')
        return hex - '0';
    if (hex >= 'A' && hex <= 'F')
        return hex - 'A' + 10;
    if (hex >= 'a' && hex <= 'f')
        return hex - 'a' + 10;
    return 255;
}

int hexstr2binary(const char *hexstr, size_t len, uint8_t *buf, size_t buflen)
{
    int i, j;

    for (i = 0, j = 0; i + 1 < len && j < buflen; i += 2, j++)
        buf[j] = (hex_char2num(hexstr[i]) << 4) | hex_char2num(hexstr[i+1]);

    return j;
}

#define num2hexchar(b)     (((b) > 9) ? ((b) - 0xa + 'A') : ((b) + '0'))
int binary2hexstr(const uint8_t *hex, size_t len, char *buf, size_t buflen)
{
    size_t i, j;

    for (i = 0, j = 0; i < len && j + 1 < buflen; i++, j += 2) {
        buf[j] = num2hexchar((hex[i] & 0xf0) >> 4);
        buf[j+1] = num2hexchar(hex[i] & 0x0f);
    }

    return j;
}

int binary2print(const uint8_t *hex, size_t len, char *buf, size_t buflen)
{
    size_t i, j;

    for (i = 0, j = 0; i < len && j < buflen; i++) {
        if (isprint(hex[i])) {
            buf[j++] = hex[i];
            if (j >= buflen)
                break;
        } else {
            if (j + 2 >= buflen)
                break;
            buf[j] = '\\';
            buf[j+1] = num2hexchar((hex[i] & 0xf0) >> 4);
            buf[j+2] = num2hexchar(hex[i] & 0x0f);
            j += 2;
        }
    }

    return j;
}

static int is_link_local(struct sockaddr *addr)
{
    unsigned char *addrbytes;
    if (addr->sa_family == AF_INET6) {
        addrbytes = (unsigned char *)(&((struct sockaddr_in6 *)addr)->sin6_addr);
        return (addrbytes[0] == 0xFE) && ((addrbytes[1] & 0xC0) == 0x80); /* fe80::/10 */
    }
    return 0;
}

int mask2prefix(const struct sockaddr *addr)
{
    int i, j;
    int pfxlen, addrlen;
    unsigned char *mask;

    if (!addr)
        return -1;

    if (addr->sa_family == AF_INET) {
        mask = (unsigned char *)&((struct sockaddr_in *)addr)->sin_addr;
        addrlen = 4;
    } else if (addr->sa_family == AF_INET6) {
        mask = (unsigned char *)&((struct sockaddr_in6 *)addr)->sin6_addr;
        addrlen = 16;
    } else {
        return -1;
    }

    pfxlen = 0;
    for (i = 0; i < addrlen; i++) {
        for (j = 7; j >= 0; j--) {
            if (mask[i] & (1U << j))
                ++pfxlen;
            else
                return pfxlen;
        }
    }
    return pfxlen;
}

int get_host_addr(const char *ifname, struct sockaddr_storage *result4,
        struct sockaddr_storage *result6, char *ifname4, char *ifname6)
{
    struct ifaddrs *ifa_head, *ifa;
    int found_v4 = 0, found_v6 = 0;
    int pfxlen, pfxlen_v4 = 0, pfxlen_v6 = 0;

    if (getifaddrs(&ifa_head) == -1)
        return -1;

    /* addresses on ifname take precedence */
    if (ifname) {
        for (ifa = ifa_head; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL)
                continue;
            if (ifa->ifa_flags & IFF_LOOPBACK ||
                    !(ifa->ifa_flags & IFF_UP) ||
                    !(ifa->ifa_flags & IFF_RUNNING))
                continue;
            if (is_link_local(ifa->ifa_addr))
                continue;
            if (strcmp(ifname, ifa->ifa_name) == 0) {
                pfxlen = mask2prefix(ifa->ifa_netmask);
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    if (!pfxlen_v4 || (pfxlen > 0 && pfxlen < pfxlen_v4)) {
                        if (result4)
                            memcpy(result4, ifa->ifa_addr, sizeof(struct sockaddr_in));
                        if (ifname4) {
                            strncpy(ifname4, ifa->ifa_name, IFNAMSIZ-1);
                            ifname4[IFNAMSIZ-1] = '\0';
                        }
                        found_v4 = 1;
                        pfxlen_v4 = pfxlen > 0 ? pfxlen : 32;
                    }
                } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                    if (!pfxlen_v6 || (pfxlen > 0 && pfxlen < pfxlen_v6)) {
                        if (result6)
                            memcpy(result6, ifa->ifa_addr, sizeof(struct sockaddr_in6));
                        if (ifname6) {
                            strncpy(ifname6, ifa->ifa_name, IFNAMSIZ-1);
                            ifname6[IFNAMSIZ-1] = '\0';
                        }
                        found_v6 = 1;
                        pfxlen_v6 = pfxlen > 0 ? pfxlen : 128;
                    }
                }
            }
        }
    }

    /* try to find address on other interfaces */
    if (!found_v4 || !found_v6) {
        for (ifa = ifa_head; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL)
                continue;
            if (ifa->ifa_flags & IFF_LOOPBACK ||
                    !(ifa->ifa_flags & IFF_UP) ||
                    !(ifa->ifa_flags & IFF_RUNNING))
                continue;
            if (is_link_local(ifa->ifa_addr))
                continue;
            pfxlen = mask2prefix(ifa->ifa_netmask);
            if (ifa->ifa_addr->sa_family == AF_INET) {
                if (!pfxlen_v4 || (pfxlen > 0 && pfxlen < pfxlen_v4)) {
                    if (result4)
                        memcpy(result4, ifa->ifa_addr, sizeof(struct sockaddr_in));
                    if (ifname4) {
                        strncpy(ifname4, ifa->ifa_name, IFNAMSIZ-1);
                        ifname4[IFNAMSIZ-1] = '\0';
                    }
                    found_v4 = 1;
                    pfxlen_v4 = pfxlen > 0 ? pfxlen : 32;
                }
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                if (!pfxlen_v6 || (pfxlen > 0 && pfxlen < pfxlen_v6)) {
                    if (result6)
                        memcpy(result6, ifa->ifa_addr, sizeof(struct sockaddr_in6));
                    if (ifname6) {
                        strncpy(ifname6, ifa->ifa_name, IFNAMSIZ-1);
                        ifname6[IFNAMSIZ-1] = '\0';
                    }
                    found_v6 = 1;
                    pfxlen_v6 = pfxlen > 0 ? pfxlen : 128;
                }
            }
        }
    }

    freeifaddrs(ifa_head);

    if (found_v4 && found_v6)
        return 3;
    if (found_v4)
        return 1;
    if (found_v6)
        return 2;
    return 0;
}
