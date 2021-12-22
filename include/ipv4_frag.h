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
#ifndef __DPVS_IPV4_FRAG_H__
#define __DPVS_IPV4_FRAG_H__

#define IP4_FRAG_FREE_DEATH_ROW_INTERVAL 100

int ipv4_frag_init(void);
int ipv4_frag_term(void);
int ipv4_reassamble(struct rte_mbuf *mbuf);
int ipv4_fragment(struct rte_mbuf *mbuf, unsigned int mtu,
          int (*output)(struct rte_mbuf *));

void ip4_frag_keyword_value_init(void);
void install_ip4_frag_keywords(void);

#endif /* __DPVS_IPV4_FRAG_H__ */
