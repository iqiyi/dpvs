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
/**
 * packet "matcher" of DPVS.
 *
 * raychen@qiyi.com, Aug. 2017, initial.
 */
#ifndef __DPVS_MATCH_H__
#define __DPVS_MATCH_H__
#include <string.h>
#include <net/if.h>
#include "inet.h"

struct dp_vs_match {
    /* TODO: add proto, ... */
    int  af;
    /* range is more flexible than prefix. */
    struct inet_addr_range srange;      /* source range */
    struct inet_addr_range drange;      /* dest range */
    char iifname[IFNAMSIZ];
    char oifname[IFNAMSIZ];
};

static inline bool is_empty_match(const struct dp_vs_match *match)
{
    const static struct dp_vs_match zero_match = {};
    return !memcmp(match, &zero_match, sizeof(*match));
}

static inline int dp_vs_match_parse(const char *srange, const char *drange,
                                    const char *iifname, const char *oifname,
                                    int af, struct dp_vs_match *match)
{
    int s_af = 0, d_af = 0, err;

    memset(match, 0, sizeof(*match));

    if (srange && strlen(srange)) {
        err = inet_addr_range_parse(srange, &match->srange, &s_af);
        if (err != EDPVS_OK)
            return err;
    }

    if (drange && strlen(drange)) {
        err = inet_addr_range_parse(drange, &match->drange, &d_af);
        if (err != EDPVS_OK)
            return err;
    }

    if (s_af && d_af && s_af != d_af) {
        return EDPVS_INVAL;
    }
    match->af = s_af | d_af;

    if (af && match->af && af != match->af) {
        return EDPVS_INVAL;
    }

    snprintf(match->iifname, IFNAMSIZ, "%s", iifname ? : "");
    snprintf(match->oifname, IFNAMSIZ, "%s", oifname ? : "");

    return EDPVS_OK;
}

static inline int parse_match(const char *pattern, uint8_t *proto,
                              struct dp_vs_match *match)
{
    char _pat[256];
    char *start, *tok, *sp, *delim = ",";
    int err;

    *proto = 0;
    memset(match, 0, sizeof(*match));
    snprintf(_pat, sizeof(_pat), "%s", pattern);

    for (start = _pat; (tok = strtok_r(start, delim, &sp)); start = NULL) {
        if (strcmp(tok, "tcp") == 0) {
            *proto = IPPROTO_TCP;
        } else if (strcmp(tok, "udp") == 0) {
            *proto = IPPROTO_UDP;
        } else if (strcmp(tok, "sctp") == 0) {
            *proto = IPPROTO_SCTP;
        } else if (strcmp(tok, "icmp") == 0) {
            *proto = IPPROTO_ICMP;
        } else if (strcmp(tok, "icmp6") == 0) {
            *proto = IPPROTO_ICMPV6;
        } else if (strncmp(tok, "from=", strlen("from=")) == 0) {
            tok += strlen("from=");

            err = inet_addr_range_parse(tok, &match->srange, &match->af);
            if (err != EDPVS_OK)
                return err;
        } else if (strncmp(tok, "to=", strlen("to=")) == 0) {
            tok += strlen("to=");

            err = inet_addr_range_parse(tok, &match->drange, &match->af);
            if (err != EDPVS_OK)
                return err;
        } else if (strncmp(tok, "iif=", strlen("iif=")) == 0) {
            tok += strlen("iif=");
            snprintf(match->iifname, IFNAMSIZ, "%s", tok);
        } else if (strncmp(tok, "oif=", strlen("oif=")) == 0) {
            tok += strlen("oif=");
            snprintf(match->oifname, IFNAMSIZ, "%s", tok);
        } else {
            return EDPVS_INVAL;
        }
    }

    return EDPVS_OK;
}

static inline char *dump_match(uint8_t proto, const struct dp_vs_match *match,
                               char *buf, size_t size)
{
    const static struct inet_addr_range zero_range = {{{0}}};
    size_t left = size;

    if (!match || !buf || size < 1)
        return NULL;

    buf[0] = '\0';
    left -= snprintf(buf + strlen(buf), left, "%s",
                     proto ? inet_proto_name(proto) : "unspec");

    if (memcmp(&match->srange, &zero_range, sizeof(zero_range)) != 0) {
        left -= snprintf(buf + strlen(buf), left, ",from=");
        left -= inet_addr_range_dump(match->af, &match->srange,
                                     buf + strlen(buf), left);
    }

    if (memcmp(&match->drange, &zero_range, sizeof(zero_range)) != 0) {
        left -= snprintf(buf + strlen(buf), left, ",to=");
        left -= inet_addr_range_dump(match->af, &match->drange,
                                     buf + strlen(buf), left);
    }

    if (strlen(match->iifname)) {
        left -= snprintf(buf + strlen(buf), left, ",iif=%s", match->iifname);
    }

    if (strlen(match->oifname)) {
        left -= snprintf(buf + strlen(buf), left, ",oif=%s", match->oifname);
    }

    return buf;
}

#endif /* __DPVS_MATCH_H__ */
