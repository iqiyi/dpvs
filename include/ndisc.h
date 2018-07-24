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
#ifndef __DPVS_NDISC_H__
#define __DPVS_NDISC_H__

#include "neigh.h"

struct nd_msg {
    struct icmp6_hdr    icmph;
    struct in6_addr    target;
    uint8_t            opt[0];
};

/*
 * netinet/icmp6.h define ND_OPT by '#define', ND_OPT_MAX is not defined.
 * kernel define ND_OPT_ARRAY_MAX by enum, ND_OPT_MTU + 1 is used instead here.
 * */
struct ndisc_options {
    struct nd_opt_hdr *nd_opt_array[ND_OPT_MTU + 1]; 
    struct nd_opt_hdr *nd_useropts;
    struct nd_opt_hdr *nd_useropts_end;
};

#define nd_opts_src_lladdr      nd_opt_array[ND_OPT_SOURCE_LINKADDR]
#define nd_opts_tgt_lladdr      nd_opt_array[ND_OPT_TARGET_LINKADDR]
#define nd_opts_pi              nd_opt_array[ND_OPT_PREFIX_INFORMATION]
#define nd_opts_pi_end          nd_opt_array[0]  //__ND_OPT_PREFIX_INFO_END
#define nd_opts_rh              nd_opt_array[ND_OPT_REDIRECTED_HEADER]
#define nd_opts_mtu             nd_opt_array[ND_OPT_MTU]

int ndisc_rcv(struct rte_mbuf *mbuf, 
              struct netif_port *dev);

void ndisc_send_dad(struct netif_port *dev, 
                    const struct in6_addr* solicit);

void ndisc_solicit(struct neighbour_entry *neigh, 
                   const struct in6_addr *saddr);

#endif /* __DPVS_NDISC_H__ */
