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
/*
 * dpvs IPv4 tunnel common codes.
 * refer linux:include/net/ip_tunnels.h
 *       linux:include/uapi/linux/if_tunnel.h
 *
 * raychen@qiyi.com, Dec 2017, initial.
 */
#ifndef __DPVS_TUNNEL_CONF_H__
#define __DPVS_TUNNEL_CONF_H__

#include <net/if.h>
#include <netinet/ip.h>
#include <endian.h>
#include "conf/sockopts.h"

#define TNLKINDSIZ              16

#define TUNNEL_F_CSUM           htobe16(0x01)
#define TUNNEL_F_ROUTING        htobe16(0x02)
#define TUNNEL_F_KEY            htobe16(0x04)
#define TUNNEL_F_SEQ            htobe16(0x08)
#define TUNNEL_F_STRICT         htobe16(0x10)
#define TUNNEL_F_REC            htobe16(0x20)
#define TUNNEL_F_VERSION        htobe16(0x40)
#define TUNNEL_F_NO_KEY         htobe16(0x80)
#define TUNNEL_F_DONT_FRAGMENT  htobe16(0x0100)
#define TUNNEL_F_OAM            htobe16(0x0200)
#define TUNNEL_F_CRIT_OPT       htobe16(0x0400)
#define TUNNEL_F_GENEVE_OPT     htobe16(0x0800)
#define TUNNEL_F_VXLAN_OPT      htobe16(0x1000)
#define TUNNEL_F_NOCACHE        htobe16(0x2000)
#define TUNNEL_F_ERSPAN_OPT     htobe16(0x4000)

struct ip_tunnel_param {
    char            ifname[IFNAMSIZ];
    char            kind[TNLKINDSIZ];
    char            link[IFNAMSIZ];
    __be16          i_flags;
    __be16          o_flags;
    __be32          i_key;
    __be32          o_key;
    struct iphdr    iph;
} __attribute__((__packed__));

#endif /* __DPVS_TUNNEL_CONF_H__ */
