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
#ifndef __DPVS_INET_CONF_H__
#define __DPVS_INET_CONF_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "conf/common.h"

#define INET_DEF_TTL        64

#define INET_MAX_PROTS      256     /* cannot change */

union inet_addr {
    struct in_addr      in;
    struct in6_addr     in6;
};

struct inet_prefix {
    int                 plen;
    union inet_addr     addr;
};

struct inet_addr_range {
    union inet_addr     min_addr;
    union inet_addr     max_addr;
    __be16              min_port;
    __be16              max_port;
};

struct inet_stats {
    uint64_t inpkts;            /* InReceives */
    uint64_t inoctets;          /* InOctets */
    uint64_t indelivers;        /* InDelivers */
    uint64_t outforwdatagrams;  /* OutForwDatagrams */
    uint64_t outpkts;           /* OutRequests */
    uint64_t outoctets;         /* OutOctets */
    uint64_t inhdrerrors;       /* InHdrErrors */
    uint64_t intoobigerrors;    /* InTooBigErrors */
    uint64_t innoroutes;        /* InNoRoutes */
    uint64_t inaddrerrors;      /* InAddrErrors */
    uint64_t inunknownprotos;   /* InUnknownProtos */
    uint64_t intruncatedpkts;   /* InTruncatedPkts */
    uint64_t indiscards;        /* InDiscards */
    uint64_t outdiscards;       /* OutDiscards */
    uint64_t outnoroutes;       /* OutNoRoutes */
    uint64_t reasmtimeout;      /* ReasmTimeout */
    uint64_t reasmreqds;        /* ReasmReqds */
    uint64_t reasmoks;          /* ReasmOKs */
    uint64_t reasmfails;        /* ReasmFails */
    uint64_t fragoks;           /* FragOKs */
    uint64_t fragfails;         /* FragFails */
    uint64_t fragcreates;       /* FragCreates */
    uint64_t inmcastpkts;       /* InMcastPkts */
    uint64_t outmcastpkts;      /* OutMcastPkts */
    uint64_t inbcastpkts;       /* InBcastPkts */
    uint64_t outbcastpkts;      /* OutBcastPkts */
    uint64_t inmcastoctets;     /* InMcastOctets */
    uint64_t outmcastoctets;    /* OutMcastOctets */
    uint64_t inbcastoctets;     /* InBcastOctets */
    uint64_t outbcastoctets;    /* OutBcastOctets */
    uint64_t csumerrors;        /* InCsumErrors */
    uint64_t noectpkts;         /* InNoECTPkts */
    uint64_t ect1pkts;          /* InECT1Pkts */
    uint64_t ect0pkts;          /* InECT0Pkts */
    uint64_t cepkts;            /* InCEPkts */
};

static inline const char *inet_proto_name(uint8_t proto)
{
    const static char *proto_names[256] = {
        [IPPROTO_TCP]     = "TCP",
        [IPPROTO_UDP]     = "UDP",
        [IPPROTO_SCTP]    = "SCTP",
        [IPPROTO_ICMP]    = "ICMP",
        [IPPROTO_ICMPV6]  = "ICMPV6",
    };

    return proto_names[proto] ? proto_names[proto] : "<unknow>";
}

static inline uint32_t inet_addr_fold(int af, const union inet_addr *addr)
{
    uint32_t addr_fold = 0;

    if (af == AF_INET) {
        addr_fold = addr->in.s_addr;
    } else if (af == AF_INET6) {
        addr_fold = addr->in6.s6_addr32[0] ^ addr->in6.s6_addr32[1] ^
                    addr->in6.s6_addr32[2] ^ addr->in6.s6_addr32[3];
    } else {
        return 0;
    }

    return addr_fold;
}

/* ip1[-ip2][:port1[-port2]] */
static inline int inet_addr_range_parse(const char *param,
                                        struct inet_addr_range *range,
                                        int *af)
{
    char _param[256], *ips, *ports = NULL;
    char *ip1, *ip2, *port1, *port2;

    if (strlen(param) == 0)
        return EDPVS_OK; /* return asap */

    snprintf(_param, sizeof(_param), "%s", param);

    ips = _param;
    if (_param[0] == '[') {
        ips++;
        ports = strrchr(_param, ']');
        if (ports == NULL)
            return EDPVS_INVAL;
        *ports++ = '\0';
        if (*ports == ':')
            *ports++ = '\0';
        else
            return EDPVS_INVAL;
    }

    /* judge ipv4 */
    if (strrchr(_param, ':') == strchr(_param, ':')) {
        ports = strrchr(_param, ':');
        if (ports)
            *ports++ = '\0';
    }

    ip1 = ips;
    ip2 = strrchr(ips, '-');
    if (ip2)
        *ip2++ = '\0';

    if (ports) {
        port1 = ports;
        port2 = strrchr(ports, '-');
        if (port2)
            *port2++ = '\0';
    } else {
        port1 = port2 = NULL;
    }

    *af = 0;
    memset(range, 0, sizeof(*range));

    if (strlen(ip1) && inet_pton(AF_INET6, ip1, &range->min_addr.in6) > 0) {
        if (ip2 && strlen(ip2)) {
            if (inet_pton(AF_INET6, ip2, &range->max_addr.in6) <= 0)
                return EDPVS_INVAL;
        } else {
            range->max_addr = range->min_addr;
        }
        *af = AF_INET6;
    } else {
        if (strlen(ip1) && inet_pton(AF_INET, ip1, &range->min_addr.in) <= 0)
            return EDPVS_INVAL;

        if (ip2 && strlen(ip2)) {
           if (inet_pton(AF_INET, ip2, &range->max_addr.in) <= 0)
               return EDPVS_INVAL;
        } else {
            range->max_addr = range->min_addr;
        }
        *af = AF_INET;
    }

    if (port1 && strlen(port1))
        range->min_port = htons(atoi(port1));

    if (port2 && strlen(port2))
        range->max_port = htons(atoi(port2));
    else
        range->max_port = range->min_port;

    return EDPVS_OK;
}

static inline int inet_addr_range_dump(int af,
                                       const struct inet_addr_range *range,
                                       char *buf, size_t size)
{
    char min_ip[64], max_ip[64];
    char min_port[16], max_port[16];

    inet_ntop(af, &range->min_addr, min_ip, sizeof(min_ip));
    inet_ntop(af, &range->max_addr, max_ip, sizeof(max_ip));
    snprintf(min_port, sizeof(min_port), "%u",  ntohs(range->min_port));
    snprintf(max_port, sizeof(max_port), "%u",  ntohs(range->max_port));

    if (af == AF_INET)
        return snprintf(buf, size, "%s-%s:%s-%s",
                    min_ip, max_ip, min_port, max_port);
    return snprintf(buf, size, "[%s-%s]:%s-%s",
                    min_ip, max_ip, min_port, max_port);
}

static inline void inet_stats_dump(const char *title, const char *prefix,
                                   const struct inet_stats *st)
{
    if (!st)
        return;

    if (title)
        printf("%s\n", title);

    printf("%s%-18s %lu\n", prefix ? : "", "InReceives:", st->inpkts);
    printf("%s%-18s %lu\n", prefix ? : "", "InOctets:", st->inoctets);
    printf("%s%-18s %lu\n", prefix ? : "", "InDelivers:", st->indelivers);
    printf("%s%-18s %lu\n", prefix ? : "", "OutForwDatagrams:", st->outforwdatagrams);
    printf("%s%-18s %lu\n", prefix ? : "", "OutRequests:", st->outpkts);
    printf("%s%-18s %lu\n", prefix ? : "", "OutOctets:", st->outoctets);
    printf("%s%-18s %lu\n", prefix ? : "", "InHdrErrors:", st->inhdrerrors);
    printf("%s%-18s %lu\n", prefix ? : "", "InTooBigErrors:", st->intoobigerrors);
    printf("%s%-18s %lu\n", prefix ? : "", "InNoRoutes:", st->innoroutes);
    printf("%s%-18s %lu\n", prefix ? : "", "InAddrErrors:", st->inaddrerrors);
    printf("%s%-18s %lu\n", prefix ? : "", "InUnknownProtos:", st->inunknownprotos);
    printf("%s%-18s %lu\n", prefix ? : "", "InTruncatedPkts:", st->intruncatedpkts);
    printf("%s%-18s %lu\n", prefix ? : "", "InDiscards:", st->indiscards);
    printf("%s%-18s %lu\n", prefix ? : "", "OutDiscards:", st->outdiscards);
    printf("%s%-18s %lu\n", prefix ? : "", "OutNoRoutes:", st->outnoroutes);
    printf("%s%-18s %lu\n", prefix ? : "", "ReasmTimeout:", st->reasmtimeout);
    printf("%s%-18s %lu\n", prefix ? : "", "ReasmReqds:", st->reasmreqds);
    printf("%s%-18s %lu\n", prefix ? : "", "ReasmOKs:", st->reasmoks);
    printf("%s%-18s %lu\n", prefix ? : "", "ReasmFails:", st->reasmfails);
    printf("%s%-18s %lu\n", prefix ? : "", "FragOKs:", st->fragoks);
    printf("%s%-18s %lu\n", prefix ? : "", "FragFails:", st->fragfails);
    printf("%s%-18s %lu\n", prefix ? : "", "FragCreates:", st->fragcreates);
    printf("%s%-18s %lu\n", prefix ? : "", "InMcastPkts:", st->inmcastpkts);
    printf("%s%-18s %lu\n", prefix ? : "", "OutMcastPkts:", st->outmcastpkts);
    printf("%s%-18s %lu\n", prefix ? : "", "InBcastPkts:", st->inbcastpkts);
    printf("%s%-18s %lu\n", prefix ? : "", "OutBcastPkts:", st->outbcastpkts);
    printf("%s%-18s %lu\n", prefix ? : "", "InMcastOctets:", st->inmcastoctets);
    printf("%s%-18s %lu\n", prefix ? : "", "OutMcastOctets:", st->outmcastoctets);
    printf("%s%-18s %lu\n", prefix ? : "", "InBcastOctets:", st->inbcastoctets);
    printf("%s%-18s %lu\n", prefix ? : "", "OutBcastOctets:", st->outbcastoctets);
    printf("%s%-18s %lu\n", prefix ? : "", "InCsumErrors:", st->csumerrors);
    printf("%s%-18s %lu\n", prefix ? : "", "InNoECTPkts:", st->noectpkts);
    printf("%s%-18s %lu\n", prefix ? : "", "InECT1Pkts:", st->ect1pkts);
    printf("%s%-18s %lu\n", prefix ? : "", "InECT0Pkts:", st->ect0pkts);
    printf("%s%-18s %lu\n", prefix ? : "", "InCEPkts:", st->cepkts);
}

#endif /* __DPVS_INET_CONF_H__ */
