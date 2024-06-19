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

#include "ipvs/quic.h"
#include "ipvs/conn.h"

/*
 * quic_parse_server extract encoded RS info from DCID in quic packet header.
 * Note there exists two header types in quic.
 * (https://datatracker.ietf.org/doc/html/rfc9000#name-packet-formats)
 *
 * Long Header Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2),
 *   Type-Specific Bits (4),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Type-Specific Payload (..),
 * }
 *
 * 1-RTT Packet {
 *   Header Form (1) = 0,
 *   Fixed Bit (1) = 1,
 *   Spin Bit (1),
 *   Reserved Bits (2),
 *   Key Phase (1),
 *   Packet Number Length (2),
 *   Destination Connection ID (0..160),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 */
union quic_header {
    struct {
#if defined(__LITTLE_ENDIAN_BITFIELD) || (__BYTE_ORDER == __LITTLE_ENDIAN)
        unsigned int typedata:4;
        unsigned int type:2;
        unsigned int fixed:1;
        unsigned int form:1;
#elif defined (__BIG_ENDIAN_BITFIELD) || (__BYTE_ORDER == __BIG_ENDIAN)
        unsigned int form:1;
        unsigned int fixed:1;
        unsigned int type:2;
        unsigned int typedata:4;
#else
#error    "Please fix <bits/endian.h>"
#endif
        unsigned char extra[0];  // version, DCID len, DCID, SCID len, SCID, packet number, payload
    } lhdr;
    struct {
#if defined(__LITTLE_ENDIAN_BITFIELD) || (__BYTE_ORDER == __LITTLE_ENDIAN)
        unsigned int pkt_num_len:2;
        unsigned int key_phase:1;
        unsigned int reserved:2;
        unsigned int spin:1;
        unsigned int fixed:1;
        unsigned int form:1;
#elif defined (__BIG_ENDIAN_BITFIELD) || (__BYTE_ORDER == __BIG_ENDIAN)
        unsigned int form:1;
        unsigned int fixed:1;
        unsigned int spin:1;
        unsigned int reserved:2;
        unsigned int key_phase:1;
        unsigned int pkt_num_len:2;
#else
#error    "Please fix <bits/endian.h>"
#endif
        unsigned char extra[0];  // DCID, packet number, payload
    } shdr;
};


static inline bool quic_server_match(const struct quic_server *qsvr,
        const struct dp_vs_dest *dest) {
    int l3len;
    const unsigned char *ptr1, *ptr2;

    if (unlikely(!qsvr->wildcard || qsvr->wildcard % 8))
        return false;
    l3len = qsvr->wildcard >> 3;

    if (AF_INET == dest->af) {
        ptr1 = ((const unsigned char *)&dest->addr) + (4 - l3len);
        ptr2 = ((const unsigned char *)&qsvr->addr) + (4 - l3len);
    } else {
        ptr1 = ((const unsigned char *)&dest->addr) + (16 - l3len);
        ptr2 = ((const unsigned char *)&qsvr->addr) + (16 - l3len);
    }

    while (l3len-- > 0) {
        if (*ptr1 != *ptr2)
            return false;
        ptr1++;
        ptr2++;
    }

    if (!qsvr->port)
        return true;
    return qsvr->port == dest->port;
}

int quic_parse_server(const struct rte_mbuf *mbuf,
        const struct dp_vs_iphdr *iph,
        struct quic_server *qsvr) {
    int offset = iph->len;
    int i, l3len, l4len;
    unsigned char *ptr, *dptr;

    union quic_header *qhdr, hdrbuf;
    uint32_t *qver, qverbuf;
    uint8_t *cidlen, cidlenbuf;
    unsigned char *cid, cidbuf[20];

    memset(qsvr, 0, sizeof(struct quic_server));

    offset += sizeof(struct rte_udp_hdr);
    qhdr = mbuf_header_pointer(mbuf, offset, sizeof(hdrbuf), &hdrbuf);
    if (unlikely(!qhdr))
        return EDPVS_INVPKT;

    if (unlikely(!qhdr->lhdr.fixed))
        return EDPVS_INVPKT;

    offset++;
    if (qhdr->lhdr.form) { // quic long header
        qver = mbuf_header_pointer(mbuf, offset, sizeof(qverbuf), &qverbuf);
        if (unlikely(NULL == qver || ntohl(*qver) > 1))
            return EDPVS_INVPKT;
        offset += sizeof(qverbuf);
        cidlen = mbuf_header_pointer(mbuf, offset, sizeof(cidlenbuf), &cidlenbuf);
        if (unlikely(NULL == cidlen || *cidlen > 20))
            return EDPVS_INVPKT;
        if (*cidlen < DPVS_QUIC_DCID_BYTES_MIN)
            return EDPVS_OK; // possible conn without DCID, or cilient Initial packets
        offset += sizeof(cidlenbuf);
        cid = mbuf_header_pointer(mbuf, offset, *cidlen, &cidbuf);
        if (unlikely(!cid))
            return EDPVS_INVPKT;
    } else { // quic short header
        cid = mbuf_header_pointer(mbuf, offset, DPVS_QUIC_DCID_BYTES_MIN, &cidbuf);
        if (NULL == cid)
            return EDPVS_OK; // possible conn without DCID
        ptr = cid + 1;
        cidlen = &cidlenbuf;
        *cidlen = ((*ptr >> 5) & 0x3) + 1;
        if (*ptr & 0x10)
            *cidlen += 2;
        *cidlen += 6;
        if (*cidlen > DPVS_QUIC_DCID_BYTES_MIN) {
            cid = mbuf_header_pointer(mbuf, offset, *cidlen, &cidbuf);
            if (unlikely(!cid))
                return EDPVS_OK; // possible conn without DCID
        }
    }

    ptr = cid;
    ++ptr; // skip first octet
    l3len = ((*ptr >> 5) & 0x7) + 1;
    l4len = (*ptr & 0x10) ? 2 : 0;

    qsvr->wildcard = l3len << 3;

    if (AF_INET == iph->af)
        dptr = ((unsigned char *)&qsvr->addr) + (4 - l3len);
    else
        dptr = ((unsigned char *)&qsvr->addr) + (16 - l3len);

    for (i = 0; i < l3len; i++, ptr++, dptr++)
        *dptr = ((*ptr & 0xf) << 4) | ((*(ptr+1) >> 4) & 0xf);

    if (l4len) {
        dptr = (unsigned char *)&qsvr->port;
        for (i = 0; i < l4len; i++, ptr++, dptr++)
            *dptr = ((*ptr & 0xf) << 4) | ((*(ptr+1) >> 4) & 0xf);
    }

    return EDPVS_OK;
}

struct dp_vs_conn* quic_schedule(const struct dp_vs_service *svc,
        const struct quic_server *qsvr,
        const struct dp_vs_iphdr *iph,
        struct rte_mbuf *mbuf) {
    bool found = false;
    struct dp_vs_dest *dest;
    uint16_t _ports[2], *ports;
    uint32_t flags = 0;
    struct dp_vs_conn_param param;
    struct dp_vs_conn *conn;

    if (unlikely(!qsvr || !qsvr->wildcard || iph->proto != IPPROTO_UDP
            || svc->flags & DP_VS_SVC_F_PERSISTENT))
        return NULL;

    list_for_each_entry(dest, &svc->dests, n_list) {
        if (quic_server_match(qsvr, dest)) {
            found = true;
            break;
        }
    }
    if (!found || dest->fwdmode == DPVS_FWD_MODE_SNAT)
        return NULL;

    ports = mbuf_header_pointer(mbuf, iph->len, sizeof(_ports), _ports);
    if (unlikely(!ports))
        return NULL;
    dp_vs_conn_fill_param(iph->af, iph->proto,
            &iph->saddr, &iph->daddr,
            ports[0], ports[1],
            0, &param);

    if (svc->flags & DP_VS_SVC_F_EXPIRE_QUIESCENT)
        flags |= DP_VS_SVC_F_EXPIRE_QUIESCENT;

    conn = dp_vs_conn_new(mbuf, iph, &param, dest, flags);
    if (!conn)
        return NULL;

    dp_vs_stats_conn(conn);
    return conn;
}
