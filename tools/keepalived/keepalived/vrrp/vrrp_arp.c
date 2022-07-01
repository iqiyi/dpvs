/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        ARP primitives.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* system includes */
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <errno.h>

/* local includes */
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "bitops.h"
#include "vrrp_scheduler.h"
#include "vrrp_arp.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif

void send_gratuitous_arp(ip_address_t *ipaddress)
{
    log_message(LOG_INFO, "send garp for addr %s.\n", 
            inet_ntop2(ipaddress->u.sin.sin_addr.s_addr));
    dpvs_send_gratuitous_arp(&(ipaddress->u.sin.sin_addr));
}

/*
 *	Gratuitous ARP init/close
 */
void gratuitous_arp_init(void)
{
    log_message(LOG_INFO, "Registering DPVS gratuitous ARP.\n");
}

void gratuitous_arp_close(void)
{
    log_message(LOG_INFO, "Unregistering DPVS gratuitous ARP.\n");
}
