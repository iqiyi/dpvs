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
#ifndef __NET__TOA_H__
#define __NET__TOA_H__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/time.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/kallsyms.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/sock.h>
#include <linux/netfilter.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/kprobes.h>
#endif

#define TOA_VERSION "2.0.0.0"

#ifdef TOA_DEBUG_ENABLE
#define TOA_DBG(msg...)                \
    do {                    \
        printk(KERN_DEBUG "[DEBUG] TOA: " msg); \
    } while (0)
#else
#define TOA_DBG(msg...)
#endif

#define TOA_INFO(msg...)                \
    do {                        \
        if (net_ratelimit())            \
            printk(KERN_INFO "TOA: " msg);    \
    } while (0)


#define TCPOPT_TOA  254

/* MUST be 4n !!!! */
#define TCPOLEN_IP4_TOA 8        /* |opcode|size|ip+port| = 1 + 1 + 6 */
#define TCPOLEN_IP6_TOA 20        /* |opcode|size|ip_of_v6+port| = 1 + 1 + 18 */

/* MUST be 4 bytes alignment */
struct toa_ip4_data {
    __u8 opcode;
    __u8 opsize;
    __u16 port;
    __u32 ip;
};

#if (defined(TOA_IPV6_ENABLE) || defined(TOA_NAT64_ENABLE))
struct  toa_ip6_data {
    __u8 opcode;
    __u8 opsize;
    __u16 port;
    struct in6_addr in6_addr;
};
#endif

#ifdef TOA_NAT64_ENABLE
struct toa_nat64_peer {
    struct in6_addr saddr;
    __u16 port;
};

/* toa socket options, now only for nat64 */
enum {
        TOA_BASE_CTL            = 4096,
        /* set */
        TOA_SO_SET_MAX          = TOA_BASE_CTL,
        /* get */
        TOA_SO_GET_LOOKUP       = TOA_BASE_CTL,
        TOA_SO_GET_MAX          = TOA_SO_GET_LOOKUP,
};
#endif

/*should be larger than enum sock_flags(net/sock.h)*/
enum toa_sock_flags {
#if defined(__x86_64__)
    SOCK_NAT64 = 63
#else
    SOCK_NAT64 = 31
#endif
};

/* statistics about toa in proc /proc/net/toa_stat */
enum {
    SYN_RECV_SOCK_TOA_CNT = 1,
    SYN_RECV_SOCK_NO_TOA_CNT,
    GETNAME_TOA_OK_CNT,
    GETNAME_TOA_MISMATCH_CNT,
    GETNAME_TOA_BYPASS_CNT,
    GETNAME_TOA_EMPTY_CNT,
#if (defined(TOA_IPV6_ENABLE) || defined(TOA_NAT64_ENABLE))
    IP6_ADDR_ALLOC_CNT,
    IP6_ADDR_FREE_CNT,
#endif
    TOA_STAT_LAST
};

struct toa_stats_entry {
    char *name;
    int entry;
};

#define TOA_STAT_ITEM(_name, _entry) { \
    .name = _name,        \
    .entry = _entry,    \
}

#define TOA_STAT_END {    \
    NULL,        \
    0,        \
}

struct toa_stat_mib {
    unsigned long mibs[TOA_STAT_LAST];
};

#define DEFINE_TOA_STAT(type, name)       \
    __typeof__(type) *name
#define TOA_INC_STATS(mib, field)         \
    (per_cpu_ptr(mib, smp_processor_id())->mibs[field]++)

#endif
