/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
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

#define PROXY_PROTO_HDR_LEN_V4 28
#define PROXY_PROTO_HDR_LEN_V6 52

#define PROXY_PROTO_V2_SIGNATURE "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
struct proxy_hdr_v2 {
    uint8_t sig[12]; /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t cmd:4,      /* 2:v2 */
            ver:4;      /* 0:LOCAL, 1:PROXY */
    uint8_t proto:4,    /* 0:UNSPEC, 1:STREAM, 2:DGRAM */
            af:4;       /* 0:AF_UNIX, 1:AF_INET, 2:AF_INET6, 3:AF_UNIX */
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

struct proxy_addr_ipv4{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
};

struct proxy_addr_ipv6{
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
};

struct proxy_addr_unix{
    uint8_t src_addr[108];
    uint8_t dst_addr[108];
};

#endif /* __DPVS_PPHDR_H__ */

