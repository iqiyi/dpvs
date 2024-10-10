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
#ifndef __DPVS_QUIC_H__
#define __DPVS_QUICH__

#include <fcntl.h>
#include "ipvs/service.h"
#include "conf/inet.h"

/*
 *  In order to support QUIC connection migration, DPVS makes an agreement on
 *  the format of QUIC Connection ID(CID) into which backend address information
 *  is encoded. Specifically, backend server should generate its QUIC CIDs complying
 *  with the format defined as below.
 *
 *  DPVS QUIC Connction ID Format {
 *      First Octet (8),
 *      L3 Address Length (3),
 *      L4 Address Flag (1),
 *      L3 Address (8...64),
 *      [ L4 Address (16) ]
 *      Nonce (32...140)
 *  }
 *
 *  The notations in CID format definition follows the RFC 9000 name notational
 *  convention. For detailed explanation, please refer to
 *  https://datatracker.ietf.org/doc/html/rfc9000#name-notational-conventions.
 *
 *  First Octet: 8 bits
 *      Allows for compatibility with ITEF QUIC-LB drafts. Not used in DPVS.
 *      https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers-19
 *  L3 Address Length: 3 bits
 *      The length of L3 Address in byte. Add 1 to the 3-bit value gets the actual
 *      length, which is in range 1...8.
 *      If the length less than legitimated length, i.e. 4 bytes for IPv4, 16 bytes
 *      for IPv6, the higher address bytes are truncated.
 *  L4 Address Flags: 1 bit
 *      Indicate whether L4 Address is included in this CID.
 *      1 - L4 Address is included
 *      0 - L4 Address is not included
 *  L3 Address: 8, 16, 24, 32, 40, 48, 56, 64 bits
 *      IPv4/IPv6 address with high bytes trimmed if necessary.
 *      Its length is specified by L3 Address Length.
 *  L4 Address: 16 bits, optional
 *      UDP port number.
 *  Nonce: 32 ~ 140 bits, and constrained by CID's max length of 160 bits
 *      This is server independent field, often filled with data generated randomly.
 *      A minimum length is 32 bits to satisfy the entropy requirement of QUIC protocol.
 *
 *  DPVS QUIC CID adopts a variable-length code style. The server information takes
 *  a fixed 4-bit for address length, and a variable 8 ~ 48 bits for L3 and L4 addresses.
 *  DPVS may not take the whole L3/L4 Address into CID to reduce the CID length. For example,
 *  if all backend server are in private network cidr 192.168.0.0/16 listening on the same
 *  server port, then the use of lowest 16-bit L3 Address without L4 Address is appropriate.
 *
 *  Note the server info in QUIC CID is not encrypted, and we don't plan to implement a quic
 *  server id allocator as required in IETF QUIC-LB drafts. This is just a simple, stateless
 *  and clear text encoding, which may subject to security vulnerability that can be exploited
 *  by an external observer to corelate CIDs of a QUIC connection easier.
 */

#define DPVS_QUIC_DCID_BYTES_MIN  7

struct quic_server {
    uint16_t wildcard;      // enum value: 8, 16, 24, 32, 40, 48, 56, 64
    uint16_t port;          // network endian
    union inet_addr addr;
};

// Generate a Quic CID accepted by DPVS. The function demos an implementation
// for CID generator that may be used by Quic server applications on RS.
//
// For example, given
//      cidlen: 10, l3len:2, l4len:2,
//      svr_ip:192.168.111.222(0xC0A86FDE), svr_port:8029(0x1F5D)
//  the function generator Quic CIDs like
//      XX36 FDE1 F5DX XXXX XXXX
//  where 'X' denotes a random hexadecimal.
//
// Params:
//   af: l3 address family, valid values are (AF_INET, AF_INET6)
//   cidlen: the expected cid total length in bytes, no less than DPVS_QUIC_DCID_BYTES_MIN
//   l3len: length in bytes of l3 address to be encoded in cid, valid values are integers (1...8)
//   l4len: length in bytes of l4 address to be encoded in cid, valid values are (0, 2)
//   svr_ip: l3 address
//   svr_port: l4 address
//   cid: the result cid buffer, the buffer size must be no less than cidlen
static inline int quic_cid_generator(int af, int cidlen,
        int l3len, int l4len, const union inet_addr *svr_ip,
        uint16_t svr_port, char *cid) {
    char rdbuf[20];
    int i, fd, ret, entropy, l4flag;
    char *l3addr;
    uint16_t l4addr;

    entropy = cidlen - l3len - l4len + 1;
    l4flag = l4len > 0 ? 1 : 0;
    if (AF_INET == af)
        l3addr = (char *)svr_ip + (4 - l3len);
    else
        l3addr = (char *)svr_ip + (16 - l3len);
    l4addr = svr_port;

    if (cidlen < DPVS_QUIC_DCID_BYTES_MIN ||
                l3len > 8 || l3len < 1 ||
                (l4len != 0 && l4len != 2) ||
                cidlen < l3len + l4len + 5)
        return -1;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;
    ret = read(fd, rdbuf, entropy);
    if (ret != entropy)
        return -1;

    cid[0] = rdbuf[0];
    cid[1] = (((l3len - 1) & 0x7) << 5)
        | ((l4flag & 0x1) << 4)
        | ((*l3addr>> 4) & 0xf);
    for (i = 0; i < l3len; i++) {
        if (i == l3len - 1)
            cid[2+i] = ((*l3addr & 0xf) << 4);
        else
            cid[2+i] = ((*l3addr & 0xf) << 4) | ((*(l3addr+1) >> 4) & 0xf);
        l3addr++;
    }
    if (l4len > 0) {
        cid[l3len+1] &= 0xf0;
        cid[l3len+1] |= ((l4addr >> 12) & 0xf);
        l4addr <<= 4;
        cid[l3len+2] = (l4addr >> 8) & 0xff;
        cid[l3len+3] = l4addr & 0xff;
    }
    cid[l3len+l4len+1] |= (rdbuf[1] & 0xf);
    memcpy(&cid[l3len+l4len+2], &rdbuf[2], entropy - 3);
    return 0;
}

static inline void quic_dump_server(const struct quic_server *qsvr,
        char *buf, int bufsize) {
    int af;
    char addrbuf[64] = { 0 };

    buf[0] = '\0';
    af = qsvr->wildcard > 32 ? AF_INET6 : AF_INET; // an approximation, not accurate
    if (NULL == inet_ntop(af, &qsvr->addr, addrbuf, sizeof(addrbuf)))
        return;
    if (AF_INET == af)
        snprintf(buf, bufsize, "%s:%d", addrbuf, ntohs(qsvr->port));
    else
        snprintf(buf, bufsize, "[%s]:%d", addrbuf, ntohs(qsvr->port));
}

// Parse backend server address information from mbuf into qsvr.
int quic_parse_server(const struct rte_mbuf *,
        const struct dp_vs_iphdr *,
        struct quic_server *);

// Schedule a dpvs conn using the backend server specified by qsvr.
// Return NULL if the backend server doesn't exists in the svc's rs list.
struct dp_vs_conn* quic_schedule(const struct dp_vs_service *,
        const struct quic_server *,
        const struct dp_vs_iphdr *,
        struct rte_mbuf *);

#endif
