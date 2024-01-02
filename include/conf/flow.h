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
 */

/*
 * flow for IPv4/IPv6 route lookup.
 * Linux Kernel is referred.
 *
 * Lei Chen <raychen@qiyi.com>, initial, Jul 2018.
 */

#ifndef __DPVS_FLOW_CONF_H__
#define __DPVS_FLOW_CONF_H__

#include <netinet/in.h>
#include "inet.h"

/* linux:include/uapi/route.h */
#define RTF_UP          0x0001      /* route usable                 */
#define RTF_GATEWAY     0x0002      /* destination is a gateway     */
#define RTF_HOST        0x0004      /* host entry (net otherwise)   */
#define RTF_REINSTATE   0x0008      /* reinstate route after tmout  */
#define RTF_DYNAMIC     0x0010      /* created dyn. (by redirect)   */
#define RTF_MODIFIED    0x0020      /* modified dyn. (by redirect)  */
#define RTF_MTU         0x0040      /* specific MTU for this route  */
#define RTF_MSS         RTF_MTU     /* Compatibility :-(            */
#define RTF_WINDOW      0x0080      /* per route window clamping    */
#define RTF_IRTT        0x0100      /* Initial round trip time      */
#define RTF_REJECT      0x0200      /* Reject route                 */

/* dpvs defined. */
#define RTF_FORWARD     0x0400
#define RTF_LOCALIN     0x0800
#define RTF_DEFAULT     0x1000
#define RTF_KNI         0X2000

typedef struct rt_addr {
    union inet_addr addr;
    int             plen; /*prefix len*/
} rt_addr_t;

#endif /* __DPVS_FLOW_CONF_H__ */
