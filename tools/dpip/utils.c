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
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "conf/common.h"
#include "dpip.h"

const char *af_itoa(int af)
{
    struct {
        uint8_t i_af;
        const char *s_af;
    } family_tab[] = {
        { AF_INET,  "inet" },
        { AF_INET6, "inet6" },
        { AF_UNSPEC, "unspec" },
    };
    int i;

    for (i = 0; i < NELEMS(family_tab); i++) {
        if (af == family_tab[i].i_af)
            return family_tab[i].s_af;
    }

    return "<unknow>";
}

bool inet_is_addr_any(int af, const union inet_addr *addr)
{
    switch (af) {
    case AF_INET:
        return addr->in.s_addr == htonl(INADDR_ANY);
    case AF_INET6:
        return IN6_ARE_ADDR_EQUAL(&addr->in6, &in6addr_any);
    default:
        return false; /* ? */
    }
}

int inet_pton_try(int *af, const char *src, union inet_addr *dst)
{
    int err;

    if (*af == AF_INET)
        err = inet_pton(AF_INET, src, &dst->in);
    else if (*af == AF_INET6)
        err = inet_pton(AF_INET6, src, &dst->in6);
    else {
        if ((err = inet_pton(AF_INET, src, &dst->in)) > 0)
            *af = AF_INET;
        else if ((err = inet_pton(AF_INET6, src, &dst->in6)) > 0)
            *af = AF_INET6;
        else
            *af = AF_UNSPEC;
    }

    if (err <= 0)
        fprintf(stderr, "invalid ipaddress: %s %s\n", af_itoa(*af), src);

    return err;
}
