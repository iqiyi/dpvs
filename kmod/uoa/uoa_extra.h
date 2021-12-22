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
#ifndef __UOA_EXTRA_H__
#define __UOA_EXTRA_H__

#ifdef UOA_NEED_EXTRA
#include <linux/ipv6.h>
#endif

union inet_addr {
    struct in_addr      in;
    struct in6_addr     in6;
};

#ifdef UOA_NEED_EXTRA
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

static inline bool inet_addr_equal(int af, const union inet_addr *a1,
                     const union inet_addr *a2)
{
    switch (af) {
        case AF_INET:
            return a1->in.s_addr == a2->in.s_addr;
        case AF_INET6:
            return memcmp(a1->in6.s6_addr, a2->in6.s6_addr, 16) == 0;
        default:
            return memcmp(a1, a2, sizeof(union inet_addr)) == 0;
    }
}

#define IN6_ARE_ADDR_EQUAL(a,b) \
    ((((const uint32_t *) (a))[0] == ((const uint32_t *) (b))[0])     \
     && (((const uint32_t *) (a))[1] == ((const uint32_t *) (b))[1])  \
     && (((const uint32_t *) (a))[2] == ((const uint32_t *) (b))[2])  \
     && (((const uint32_t *) (a))[3] == ((const uint32_t *) (b))[3]))

static inline bool inet_is_addr_any(int af, const union inet_addr *addr)
{
    switch (af) {
        case AF_INET:
            return addr->in.s_addr == htonl(INADDR_ANY);
        case AF_INET6:
        {
            struct in6_addr ip6adummy = IN6ADDR_ANY_INIT;
            return IN6_ARE_ADDR_EQUAL(&addr->in6, &ip6adummy);
        }
        default:
            return false;
    }
}
#endif

#endif /* ifndef __UOA_EXTRA_H_ */
