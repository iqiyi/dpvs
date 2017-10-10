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
#ifndef __DPVS_ICMP_H__
#define __DPVS_ICMP_H__
#include <netinet/ip_icmp.h>

int icmp_init(void);
int icmp_term(void);

void icmp_send(struct rte_mbuf *imbuf, int type, int code, uint32_t info);

#define icmp4_id(icmph)      (((icmph)->un).echo.id)

#endif /* __DPVS_ICMP_H__ */
