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
 *
 * UDP Option of Address (UOA) Kernel Module for Real Server.
 * it refers TOA of LVS and ip_vs kernel module.
 *
 * raychen@qiyi.com, Feb 2018, initial.
 *                   May 2018, add private "Option Protocol".
 */

#ifndef __DPVS_UOA__
#define __DPVS_UOA__
#ifdef __KERNEL__
#include <asm/byteorder.h>
#else
#include <endian.h>
#endif

/* avoid IANA ip options */
#define IPOPT_UOA        (31 | IPOPT_CONTROL)
#define IPOLEN_UOA_IPV4  (sizeof(struct ipopt_uoa) + 4)
#define IPOLEN_UOA_IPV6  (sizeof(struct ipopt_uoa) + 16)

/*
 * UOA IP option
 * @op_code: operation code
 * @op_len:  length of (struct ipopt_uoa) + real op_addr (v4/v6) length
 *           i.e. IPOLEN_UOA_IPV4 or IPOLEN_UOA_IPV6
 * @op_port: port number
 * @op_addr: real ipv4 or ipv6 address following it
 */
struct ipopt_uoa {
    __u8    op_code;
    __u8    op_len;
    __be16  op_port;
    __u8    op_addr[0];
} __attribute__((__packed__));

/* per-cpu statistics */
struct uoa_cpu_stats {
    __u64   uoa_got;    /* UDP packet got UOA. */
    __u64   uoa_none;    /* UDP packet has no UOA. */
    __u64   uoa_saved;    /* UOA saved to mapping table */
    __u64   uoa_ack_fail;    /* Fail to send UOA ACK. */
    __u64   uoa_miss;    /* Fail to get UOA info from pkt. */

    __u64   success;    /* uoa address returned. */
    __u64   miss;        /* no such uoa info . */
    __u64   invalid;    /* bad uoa info found. */

#ifdef __KERNEL__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
    struct u64_stats_sync syncp;
#endif
#endif
} __attribute__((__packed__));

/* normal kernel statistics (global) */
struct uoa_kstats {
    __u64   uoa_got;    /* UDP packet got UOA. */
    __u64   uoa_none;    /* UDP packet has no UOA. */
    __u64   uoa_saved;    /* UOA saved to mapping table */
    __u64   uoa_ack_fail;    /* Fail to shand UOA ACK. */
    __u64   uoa_miss;    /* Fail to get UOA info from pkt. */

    __u64   success;    /* uoa address returned. */
    __u64   miss;        /* no such uoa info . */
    __u64   invalid;    /* bad uoa info found. */
} __attribute__((__packed__));

/* uoa socket options */
enum {
    UOA_BASE_CTL        = 2048,
    /* set */
    UOA_SO_SET_MAX        = UOA_BASE_CTL,
    /* get */
    UOA_SO_GET_LOOKUP    = UOA_BASE_CTL,
    UOA_SO_GET_MAX        = UOA_SO_GET_LOOKUP,
};

struct uoa_param_map {
    /* input */
    __be16           af;
    union inet_addr  saddr;
    union inet_addr  daddr;
    __be16           sport;
    __be16           dport;
    /* output */
    __be16           real_af;
    union inet_addr  real_saddr;
    __be16           real_sport;
} __attribute__((__packed__));

/**
 * Why use private IP protocol for Address ?
 *
 * we found not all l3-switch support IPv4 options,
 * or even if support, there's speed limitation like 300pps.
 *
 * the reason from provider is the switch HW (chips) do not
 * handle IP options, just have to drop the whole packet.
 * or pass the pkt with option to CPU for process, with a
 * limited speed which is too poor to accept.
 *
 * On the other hand, the switch can "support" unkown IP
 * protocol, we can forwarding this kind of packets.
 *
 * Why not use GRE ? there's no space for insert private data
 * like client IP/port.
 */

/**
 *  "Option Protocol": IPPROTO_OPT
 *
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +---------------+---------------+---------------+--------------+
 *  |  Ver. | Rsvd. |    Protocol   |            Length            |
 *  +---------------+---------------+---------------+--------------+
 *  :                           Options                            :
 *  +---------------+---------------+---------------+--------------+
 *
 *  Ve.     Version, now 0x1 (1) for ipv4 address family, OPPHDR_IPV4
 *                       0x2 (2) for ipv6 address family, OPPHDR_IPV6
 *  Rsvd.   Reserved bits, must be zero.
 *  Protocol    Next level protocol, e.g., IPPROTO_UDP.
 *  Length    Length of fixed header and options, not include payloads.
 *  Options    Compatible with IPv4 options, including IPOPT_UOA.
 */

#define IPPROTO_OPT    0xf8 /* 248 */

#define OPPHDR_IPV6 0x02
#define OPPHDR_IPV4 0x01

/* OPtion Protocol header */
struct opphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD) || (__BYTE_ORDER == __LITTLE_ENDIAN)
    unsigned int rsvd0:4;
    unsigned int version:4;
#elif defined (__BIG_ENDIAN_BITFIELD) || (__BYTE_ORDER == __BIG_ENDIAN)
    unsigned int version:4;
    unsigned int rsvd0:4;
#else
#ifndef __KERNEL__
# error    "Please fix <bits/endian.h>"
#else
# error    "Please fix <asm/byteorder.h>"
#endif
#endif
    __u8    protocol;    /* IPPROTO_XXX */
    __be16    length;        /* length of fixed header and options */
    __u8    options[0];
} __attribute__((__packed__));

#endif
