/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2023 iQIYI (www.iqiyi.com).
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
#ifndef __DPVS_PPHDR_H__
#define __DPVS_PPHDR_H__

#include <netinet/tcp.h>
#include <stdint.h>
#include "dpdk.h"
#include "ipvs/proxy_proto.h"
#include "ipvs/conn.h"

/*
 * DPVS Implementation of Proxy Protocol:
 *   https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt
 */

#define PROXY_PROTO_V1_MAX_DATALEN  107
#define PROXY_PROTO_HDR_LEN_V4      28
#define PROXY_PROTO_HDR_LEN_V6      52
#define PROXY_PROTO_HDR_LEN_UX      232

#define PROXY_PROTO_V2_SIGNATURE    "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
#define PROXY_PROTO_V2_AF_MAX       4
#define PROXY_PROTO_V2_PROTO_MAX    3


struct proxy_hdr_v2 {
    uint8_t sig[12];            // \x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t cmd:4,              // 0:LOCAL, 1:PROXY
            ver:4;              // 2:v2
    uint8_t proto:4,            // 0:UNSPEC, 1:STREAM, 2:DGRAM
            af:4;               // 0:AF_UNIX, 1:AF_INET, 2:AF_INET6, 3:AF_UNIX
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ver:4,
            cmd:4;
    uint8_t af:4,
            proto:4;
#else
#error "Please fix <bits/endian.h>"
#endif
    uint16_t addrlen;
} __attribute__((__packed__));

struct proxy_addr_ipv4 {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
};

struct proxy_addr_ipv6 {
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
};

struct proxy_addr_unix {
    uint8_t src_addr[108];
    uint8_t dst_addr[108];
};

typedef union {
    struct {
        char line[108];
    } v1;
    struct {
        struct proxy_hdr_v2 hdr;
        union {
            struct proxy_addr_ipv4 ip4;
            struct proxy_addr_ipv6 ip6;
            struct proxy_addr_unix unx;
        } addr;
    } v2;
} __attribute__((__packed__)) proxy_proto_t;

struct proxy_info {
    uint8_t af;         /* AF_INET, AF_INET6, AF_UNIX */
    uint8_t proto;      /* IPPROTO_TCP, IPPROTO_UDP */
    uint8_t version;    /* proxy protocol version */
    uint8_t cmd;        /* proxy protocol command, 0:LOCAL, 1:PROXY */
    uint16_t datalen;   /* length of the encoded proxy protocol data in packet,
                           MUST be ZERO when the proxy_info isn't parsed from mbuf */
    union {
        struct proxy_addr_ipv4 ip4;
        struct proxy_addr_ipv6 ip6;
        struct proxy_addr_unix unx;
    } addr;
};

static inline uint8_t ppv2_af_pp2host(uint8_t ppv2af)
{
    static uint8_t aftable[PROXY_PROTO_V2_AF_MAX] = {
            AF_UNSPEC, AF_INET, AF_INET6, AF_UNIX};
    if (unlikely(ppv2af >= PROXY_PROTO_V2_AF_MAX))
        return AF_UNSPEC;
    return aftable[ppv2af];
}

static inline uint8_t ppv2_af_host2pp(uint8_t hostaf)
{
    static uint8_t aftable[AF_MAX] = {
        [ AF_UNSPEC ]   = 0,
        [ AF_INET   ]   = 1,
        [ AF_INET6  ]   = 2,
        [ AF_UNIX   ]   = 3,
    };
    if (unlikely(hostaf >= AF_MAX))
        return 0;
    return aftable[hostaf];
}

static inline uint8_t ppv2_proto_pp2host(uint8_t ppv2proto)
{
    switch (ppv2proto) {
        case 1:
            return IPPROTO_TCP;
        case 2:
            return IPPROTO_UDP;
    }
    return 0; /* IPPROTO_IP */
}

static inline uint8_t ppv2_proto_host2pp(uint8_t hostproto)
{
    switch (hostproto) {
        case IPPROTO_TCP:
            return 1;
        case IPPROTO_UDP:
            return 2;
    }
    return 0;
}

int proxy_proto_parse(struct rte_mbuf *mbuf, int ppdoff, struct proxy_info *ppinfo);
int proxy_proto_insert(struct proxy_info *ppinfo, struct dp_vs_conn *conn,
        struct rte_mbuf *mbuf, void *l4hdr, int *hdr_shift);

#endif /* __DPVS_PPHDR_H__ */

