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
#ifndef __DPIP_UTILS_H__
#define __DPIP_UTILS_H__
#include "conf/inet.h"

#define __init __attribute__((constructor))
#define __exit __attribute__((destructor))

#define NEXTARG(c)          ((c)->argc--, (c)->argv++)

#define NEXTARG_CHECK(c, m) do { \
    /* expand the macro before NEXTARG */ \
    const char *__arg_str = (m); \
    NEXTARG((c)); \
    if ((c)->argc <= 0) { \
        fprintf(stderr, "missing argument for `%s'\n", (__arg_str)); \
        return -1; \
    } \
} while (0)

#define CURRARG(c)          ((c)->argv[0])

const char *af_itoa(int af);

bool inet_is_addr_any(int af, const union inet_addr *addr);
int inet_pton_try(int *af, const char *src, union inet_addr *dst);

#endif /* __DPIP_UTILS_H__ */
