/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2018 iQIYI (www.iqiyi.com).
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
 * flow for IPv4/IPv6 route lookup.
 * Linux Kernel is referred.
 *
 * Lei Chen <raychen@qiyi.com>, initial, Jul 2018.
 */
#ifndef __DPVS_FLOW_H__
#define __DPVS_FLOW_H__

#ifdef __DPVS__
#include "common.h"
#include "netif.h"
#include "inet.h"
#endif

/* linux:include/uapi/route.h */
#define RTF_UP          0x0001      /* route usable                 */
#define RTF_GATEWAY     0x0002      /* destination is a gateway     */
#define RTF_HOST        0x0004      /* host entry (net otherwise)   */
#define RTF_REINSTATE   0x0008      /* reinstate route after tmout  */
#define RTF_DYNAMIC     0x0010      /* created dyn. (by redirect)   */
#define RTF_MODIFIED    0x0020      /* modified dyn. (by redirect)  */
#define RTF_MTU         0x0040      /* specific MTU for this route  */
#define RTF_MSS         RTF_MTU     /* Compatibility :-(            */
#define RTF_WINDOW      0x0080      /* per route window clamping    */
#define RTF_IRTT        0x0100      /* Initial round trip time      */
#define RTF_REJECT      0x0200      /* Reject route                 */

/* dpvs defined. */
#define RTF_FORWARD     0x0400
#define RTF_LOCALIN     0x0800
#define RTF_DEFAULT     0x1000
#define RTF_KNI         0X2000
#define RTF_OUTWALL     0x4000

struct rt6_prefix {
    struct in6_addr     addr;
    int                 plen;
};

#ifdef __DPVS__
/* common flow info of upper layer (l4) */
union flow_ul {
    struct {
        __be16          dport;
        __be16          sport;
    } ports;

    struct {
        __u8            type;
        __u8            code;
    } icmpt;

    __be32              gre_key;
};

/* common flow info */
struct flow_common {
    struct netif_port   *flc_oif;
    struct netif_port   *flc_iif;
    uint8_t             flc_tos;
    uint8_t             flc_proto;
    uint8_t             flc_scope;
    uint8_t             flc_ttl;
    uint32_t            flc_mark;
    uint32_t            flc_flags;
};

struct flow4 {
    struct flow_common  __fl_common;
#define fl4_oif         __fl_common.flc_oif
#define fl4_iif         __fl_common.flc_iif
#define fl4_tos         __fl_common.flc_tos
#define fl4_proto       __fl_common.flc_proto
#define fl4_scope       __fl_common.flc_scope
#define fl4_ttl         __fl_common.flc_ttl
#define fl4_mark        __fl_common.flc_mark
#define fl4_flags       __fl_common.flc_flags

    struct in_addr      fl4_saddr;
    struct in_addr      fl4_daddr;

    union flow_ul       __fl_ul;
#define fl4_sport       __fl_ul.ports.sport
#define fl4_dport       __fl_ul.ports.dport
};

struct flow6 {
    struct flow_common  __fl_common;
#define fl6_oif         __fl_common.flc_oif
#define fl6_iif         __fl_common.flc_iif
#define fl6_tos         __fl_common.flc_tos
#define fl6_proto       __fl_common.flc_proto
#define fl6_scope       __fl_common.flc_scope
#define fl6_ttl         __fl_common.flc_ttl
#define fl6_mark        __fl_common.flc_mark
#define fl6_flags       __fl_common.flc_flags

    struct in6_addr     fl6_daddr;
    struct in6_addr     fl6_saddr;
    __be32              fl6_flow;

    union flow_ul       __fl_ul;
#define fl6_sport       __fl_ul.ports.sport
#define fl6_dport       __fl_ul.ports.dport
};

#endif /* __DPVS__ */
#endif /* __DPVS_FLOW_H__ */
