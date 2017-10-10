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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <unistd.h>
#include <netpacket/packet.h>

/* local includes */
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "vrrp_arp.h"


/* Build a gratuitous ARP message over a specific interface */
int send_gratuitous_arp(ip_address_t *ipaddress)
{
    log_message(LOG_INFO, "send garp for addr %s.\n", 
            inet_ntop2(ipaddress->u.sin.sin_addr.s_addr));
    return ipvs_send_gratuitous_arp(&(ipaddress->u.sin.sin_addr));
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
