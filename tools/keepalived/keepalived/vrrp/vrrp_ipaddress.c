/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 address manipulation.
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

#include <string.h>
/* local include */
#include "vrrp_ipaddress.h"
#include "vrrp_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"

/* Add/Delete IP address to a specific interface_t */

static void dpvs_fill_addrconf(ip_address_t *ipaddress, char *dpdk_port, struct inet_addr_param *param)
{
    param->af = ipaddress->ifa.ifa_family;
    if (dpdk_port) {
        strcpy(param->ifname, dpdk_port);
    } else {
        strcpy(param->ifname, ipaddress->ifp->ifname);
    }
    if (param->af == AF_INET)
        param->addr.in  = ipaddress->u.sin.sin_addr;
    else
        param->addr.in6 = ipaddress->u.sin6_addr;
    param->plen = ipaddress->ifa.ifa_prefixlen;
    param->flags &= ~IFA_F_SAPOOL;
}

static int
netlink_ipaddress(ip_address_t *ipaddress, char *dpdk_port, int cmd)
{
    struct inet_addr_param param;
    int err;
    memset(&param, 0, sizeof(param));
    dpvs_fill_addrconf(ipaddress, dpdk_port, &param);
    err = ipvs_set_ipaddr(&param, cmd);

    if (err) {
        char addr_str[64];
        void *addr = (IP_IS6(ipaddress)) ? (void *) &ipaddress->u.sin6_addr :
              (void *) &ipaddress->u.sin.sin_addr;
        inet_ntop(IP_FAMILY(ipaddress), addr, addr_str, 41);
        log_message(LOG_INFO, "ip address %s cmd %s failed\n", addr_str, \
                            cmd == IPADDRESS_DEL ? "del" : "add");
        return -1;
    }
    return 1;
}

/* Add/Delete a list of IP addresses */
void
netlink_iplist(list ip_list, int cmd, char *dpdk_port)
{
    ip_address_t *ipaddr;
    element e;

    /* No addresses in this list */
    if (LIST_ISEMPTY(ip_list))
         return;

    /*
     * If "--dont-release-vrrp" (debug & 8) is set then try to release
     * addresses that may be there, even if we didn't set them.
     */
    for (e = LIST_HEAD(ip_list); e; ELEMENT_NEXT(e)) {
         ipaddr = ELEMENT_DATA(e);
         if ((cmd && !ipaddr->set) ||
             (!cmd && (ipaddr->set || debug & 8))) {
                 if (netlink_ipaddress(ipaddr, dpdk_port, cmd) > 0)
                     ipaddr->set = (cmd) ? 1 : 0;
                 else
                     ipaddr->set = 0;
         }
    }
}

/* IP address dump/allocation */
void
free_ipaddress(void *if_data)
{
	ip_address_t *ipaddr = if_data;

	FREE_PTR(ipaddr->label);
	FREE(ipaddr);
}
char *
ipaddresstos(ip_address_t *ipaddress)
{
	char *addr_str = (char *) MALLOC(INET6_ADDRSTRLEN);

    if (!ipaddress)
        return addr_str;

	if (IP_IS6(ipaddress)) {
		inet_ntop(AF_INET6, &ipaddress->u.sin6_addr, addr_str, INET6_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET, &ipaddress->u.sin.sin_addr, addr_str, INET_ADDRSTRLEN);
	}

	return addr_str;
}
void
dump_ipaddress(void *if_data)
{
	ip_address_t *ipaddr = if_data;
	char *broadcast = (char *) MALLOC(INET_ADDRSTRLEN + 5);
	char *addr_str;

	addr_str = ipaddresstos(ipaddr);
	if (!IP_IS6(ipaddr) && ipaddr->u.sin.sin_brd.s_addr) {
		snprintf(broadcast, 21, " brd %s",
			 inet_ntop2(ipaddr->u.sin.sin_brd.s_addr));
	}

	log_message(LOG_INFO, "     %s/%d%s dev %s scope %s%s%s"
			    , addr_str
			    , ipaddr->ifa.ifa_prefixlen
			    , broadcast
			    , IF_NAME(ipaddr->ifp)
			    , netlink_scope_n2a(ipaddr->ifa.ifa_scope)
			    , ipaddr->label ? " label " : ""
			    , ipaddr->label ? ipaddr->label : "");
	FREE(broadcast);
	FREE(addr_str);
}
ip_address_t *
parse_ipaddress(ip_address_t *ip_address, char *str)
{
	ip_address_t *new = ip_address;
	void *addr;
	char *p;

	/* No ip address, allocate a brand new one */
	if (!new) {
		new = (ip_address_t *) MALLOC(sizeof(ip_address_t));
	}

	/* Handle the specials */
	if (!strcmp(str, "default")) {
		new->ifa.ifa_family = AF_INET;
		return new;
	} else if (!strcmp(str, "default6")) {
		new->ifa.ifa_family = AF_INET6;
		return new;
	}

	/* Parse ip address */
	new->ifa.ifa_family = (strchr(str, ':')) ? AF_INET6 : AF_INET;
	new->ifa.ifa_prefixlen = (IP_IS6(new)) ? 128 : 32;
	p = strchr(str, '/');
	if (p) {
		new->ifa.ifa_prefixlen = atoi(p + 1);
		*p = 0;
	}

	addr = (IP_IS6(new)) ? (void *) &new->u.sin6_addr :
			       (void *) &new->u.sin.sin_addr;
	if (!inet_pton(IP_FAMILY(new), str, addr)) {
		log_message(LOG_INFO, "VRRP parsed invalid IP %s. skipping IP...", str);
		FREE(new);
		new = NULL;
	}

	/* Restore slash */
	if (p) {
		*p = '/';
	}

	return new;
}
void
alloc_ipaddress(list ip_list, vector_t *strvec, interface_t *ifp)
{
	ip_address_t *new;
	interface_t *ifp_local;
	char *str;
	int i = 0, addr_idx =0;

	new = (ip_address_t *) MALLOC(sizeof(ip_address_t));
	if (ifp) {
		new->ifa.ifa_index = IF_INDEX(ifp);
		new->ifp = ifp;
	} else {
		ifp_local = if_get_by_ifname(DFLT_INT);
		if (!ifp_local) {
			log_message(LOG_INFO, "Default interface " DFLT_INT
				    " does not exist and no interface specified. "
				    "Skip VRRP address.");
			FREE(new);
			return;
		}
		new->ifa.ifa_index = IF_INDEX(ifp_local);
		new->ifp = ifp_local;
	}

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = vector_slot(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "dev")) {
			ifp_local = if_get_by_ifname(vector_slot(strvec, ++i));
			if (!ifp_local) {
				log_message(LOG_INFO, "VRRP is trying to assign VIP to unknown %s"
				       " interface !!! go out and fix your conf !!!",
				       (char *)vector_slot(strvec, i));
				FREE(new);
				return;
			}
			new->ifa.ifa_index = IF_INDEX(ifp_local);
			new->ifp = ifp_local;
		} else if (!strcmp(str, "scope")) {
			new->ifa.ifa_scope = netlink_scope_a2n(vector_slot(strvec, ++i));
		} else if (!strcmp(str, "broadcast") || !strcmp(str, "brd")) {
			if (IP_IS6(new)) {
				log_message(LOG_INFO, "VRRP is trying to assign a broadcast %s to the IPv6 address %s !!?? "
						      "WTF... skipping VIP..."
						    , vector_slot(strvec, i), vector_slot(strvec, addr_idx));
				FREE(new);
				return;
			} else if (!inet_pton(AF_INET, vector_slot(strvec, ++i), &new->u.sin.sin_brd)) {
				log_message(LOG_INFO, "VRRP is trying to assign invalid broadcast %s. "
						      "skipping VIP...", vector_slot(strvec, i));
				FREE(new);
				return;
			}
		} else if (!strcmp(str, "label")) {
			new->label = MALLOC(IFNAMSIZ);
			strncpy(new->label, vector_slot(strvec, ++i), IFNAMSIZ);
		} else {
			if (!parse_ipaddress(new, str))
				return;

			addr_idx  = i;
		}
		i++;
	}

	list_add(ip_list, new);
}



/* Find an address in a list */
int
address_exist(list l, ip_address_t *ipaddress, char *old_dpdk_port, char *dpdk_port)
{
	ip_address_t *ipaddr;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);
		if (ipaddr->u.sin.sin_addr.s_addr ==
            ipaddress->u.sin.sin_addr.s_addr &&
            !strcmp(old_dpdk_port, dpdk_port)) {
			ipaddr->set = ipaddress->set;
			return 1;
		}
	}

	return 0;
}

/* Clear diff addresses */
void
clear_diff_address(list l, list n, char *old_dpdk_port,char *dpdk_port)
{
	ip_address_t *ipaddr;
	element e;
	char *addr_str;
	void *addr;

	/* No addresses in previous conf */
	if (LIST_ISEMPTY(l))
		return;

	/* All addresses removed */
	if (LIST_ISEMPTY(n)) {
		log_message(LOG_INFO, "Removing a VIP|E-VIP block");
		netlink_iplist(l, IPADDRESS_DEL, old_dpdk_port);
		return;
	}

	addr_str = (char *) MALLOC(41);
	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);

		if (!address_exist(n, ipaddr, old_dpdk_port, dpdk_port)
                && ipaddr->set) {
			addr = (IP_IS6(ipaddr)) ? (void *) &ipaddr->u.sin6_addr :
						  (void *) &ipaddr->u.sin.sin_addr;
			inet_ntop(IP_FAMILY(ipaddr), addr, addr_str, 41);

			log_message(LOG_INFO, "ip address %s/%d dev %s, no longer exist"
					    , addr_str
					    , ipaddr->ifa.ifa_prefixlen
					    , IF_NAME(if_get_by_ifindex(ipaddr->ifa.ifa_index)));
			netlink_ipaddress(ipaddr, old_dpdk_port, IPADDRESS_DEL);
		}
	}
	FREE(addr_str);
}

/* Clear static ip address */
void
clear_diff_saddresses(void)
{
	clear_diff_address(old_vrrp_data->static_addresses, vrrp_data->static_addresses, NULL, NULL);
}
