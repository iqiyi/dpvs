/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 routes manipulation.
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
#include "vrrp_iproute.h"
#include "vrrp_netlink.h"
#include "vrrp_if.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"

/*
 * refer to function netlink_scope_a2n
 * */
static int scope_n2dpvs(int scope)
{
    if (scope == 254)
        return ROUTE_CF_SCOPE_HOST;
    if (scope == 253)
        return ROUTE_CF_SCOPE_LINK;
    if (scope == 0)
        return ROUTE_CF_SCOPE_GLOBAL;
    return ROUTE_CF_SCOPE_GLOBAL;
}

static int flag_n2dpvs(int scope)
{
    if (scope == 254)
        return RTF_LOCALIN;
    if (scope == 253)
        return RTF_FORWARD; 
    return RTF_FORWARD;
}

void dpvs_fill_rt4conf(ip_route_t *iproute, struct dp_vs_route_conf *route_conf)
{
    route_conf->af = AF_INET;
    (route_conf->dst).in  = (iproute->dst->u).sin.sin_addr;
    route_conf->plen = iproute->dmask;

    if (iproute->gw){
        (route_conf->via).in = (iproute->gw->u).sin.sin_addr;
    } else {
        (route_conf->via).in.s_addr = 0;
    }

    if (iproute->src){
        (route_conf->src).in = (iproute->src->u).sin.sin_addr;
    } else {
        (route_conf->src).in.s_addr = 0;
    }

    route_conf->scope = scope_n2dpvs(iproute->scope);    
    strcpy(route_conf->ifname, iproute->ifname);
    route_conf->mtu = 0;
    route_conf->metric = 0;
}

void dpvs_fill_rt6conf(ip_route_t *iproute, struct dp_vs_route6_conf *rt6_cfg) 
{
    rt6_cfg->dst.addr = ((iproute->dst)->u).sin6_addr;
    rt6_cfg->dst.plen = iproute->dmask;
    rt6_cfg->src.plen = 128;
    if (iproute->gw) {
        rt6_cfg->gateway = (iproute->gw->u).sin6_addr;
    } else {
        memset(&rt6_cfg->gateway, 0, sizeof(rt6_cfg->gateway));
    }

    if (iproute->src) {
        rt6_cfg->src.addr = (iproute->src->u).sin6_addr;
    } else {
        memset(&rt6_cfg->src, 0, sizeof(rt6_cfg->src));
    }

    rt6_cfg->flags |= flag_n2dpvs(iproute->scope);
    strcpy(rt6_cfg->ifname, iproute->ifname);
    rt6_cfg->mtu = 0;
}

int
netlink_route(ip_route_t *iproute, int cmd)
{
    char *tmp_dst,*tmp_src;

    tmp_dst = ipaddresstos(iproute->dst);
    tmp_src = ipaddresstos(iproute->src);
    
    log_message(LOG_INFO, "ip route %d %s/%d src %s port %s scope %d",
            cmd, tmp_dst, iproute->dmask, tmp_src, iproute->ifname, iproute->scope);
    FREE(tmp_dst);
    FREE(tmp_src);

    if (iproute->dst->ifa.ifa_family == AF_INET) {
        struct dp_vs_route_conf *route_conf;
        route_conf = (struct dp_vs_route_conf *)malloc(sizeof(struct dp_vs_route_conf));
        memset(route_conf, 0, sizeof(*route_conf));
        dpvs_fill_rt4conf(iproute, route_conf);
        ipvs_set_route(route_conf, cmd);
    } else {
        struct dp_vs_route6_conf *rt6_cfg;
        rt6_cfg = (struct dp_vs_route6_conf *)malloc(sizeof(struct dp_vs_route6_conf));
        memset(rt6_cfg, 0, sizeof(*rt6_cfg));
        dpvs_fill_rt6conf(iproute, rt6_cfg);
        ipvs_set_route6(rt6_cfg, cmd);
    }
    return 1;
}

/* Add/Delete a list of IP routes */
void
netlink_rtlist(list rt_list, int cmd)
{
	ip_route_t *iproute;
	element e;

	/* No routes to add */
	if (LIST_ISEMPTY(rt_list))
		return;

	for (e = LIST_HEAD(rt_list); e; ELEMENT_NEXT(e)) {
		iproute = ELEMENT_DATA(e);
		if ((cmd && !iproute->set) ||
		    (!cmd && iproute->set)) {
			if (netlink_route(iproute, cmd) > 0)
				iproute->set = (cmd) ? 1 : 0;
			else
				iproute->set = 0;
		}
	}
}

/* Route dump/allocation */
void
free_iproute(void *rt_data)
{
	FREE(rt_data);
}
void
dump_iproute(void *rt_data)
{
	ip_route_t *route = rt_data;
	char *log_msg = MALLOC(1024);
	char *tmp = MALLOC(INET6_ADDRSTRLEN + 30);
	char *tmp_str;

	if (route->blackhole) {
		strncat(log_msg, "blackhole ", 30);
	}
	if (route->dst) {
		tmp_str = ipaddresstos(route->dst);
		snprintf(tmp, INET6_ADDRSTRLEN + 30, "%s/%d", tmp_str, route->dmask);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
		FREE(tmp_str);
	}
	if (route->gw) {
		tmp_str = ipaddresstos(route->gw);
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " gw %s", tmp_str);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
		FREE(tmp_str);
	}
	if (route->gw2) {
		tmp_str = ipaddresstos(route->gw2);
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " or gw %s", tmp_str);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
		FREE(tmp_str);
	}
	if (route->src) {
		tmp_str = ipaddresstos(route->src);
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " src %s", tmp_str);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
		FREE(tmp_str);
	}
	if (route->ifname) {
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " dev %s",route->ifname);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}
	if (route->table) {
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " table %d", route->table);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}
	if (route->scope) {
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " scope %s",
			 netlink_scope_n2a(route->scope));
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}
	if (route->metric) {
		snprintf(tmp, INET6_ADDRSTRLEN + 30, " metric %d", route->metric);
		strncat(log_msg, tmp, INET6_ADDRSTRLEN + 30);
	}

	log_message(LOG_INFO, "     %s", log_msg);

	FREE(tmp);
	FREE(log_msg);
}
void
alloc_route(list rt_list, vector_t *strvec)
{
	ip_route_t *new;
	char *str;
	int i = 0;

	new = (ip_route_t *) MALLOC(sizeof(ip_route_t));

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = vector_slot(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "blackhole")) {
			new->blackhole = 1;
			new->dst = parse_ipaddress(NULL, vector_slot(strvec, ++i));
			new->dmask = new->dst->ifa.ifa_prefixlen;
		} else if (!strcmp(str, "via") || !strcmp(str, "gw")) {
			new->gw = parse_ipaddress(NULL, vector_slot(strvec, ++i));
		} else if (!strcmp(str, "or")) {
			new->gw2 = parse_ipaddress(NULL, vector_slot(strvec, ++i));
		} else if (!strcmp(str, "src")) {
			new->src = parse_ipaddress(NULL, vector_slot(strvec, ++i));
		} else if (!strcmp(str, "dev") || !strcmp(str, "oif")) {
            strcpy (new->ifname, vector_slot(strvec, ++i));
		} else if (!strcmp(str, "table")) {
			new->table = atoi(vector_slot(strvec, ++i));
		} else if (!strcmp(str, "metric")) {
			new->metric = atoi(vector_slot(strvec, ++i));
		} else if (!strcmp(str, "scope")) {
			new->scope = netlink_scope_a2n(vector_slot(strvec, ++i));
		} else {
			if (!strcmp(str, "to")) i++;

			new->dst = parse_ipaddress(NULL, vector_slot(strvec, i));
			if (new->dst) {
				new->dmask = new->dst->ifa.ifa_prefixlen;
			}
		}
		i++;
	}

	list_add(rt_list, new);
}

/* Try to find a route in a list */
int
route_exist(list l, ip_route_t *iproute)
{
	ip_route_t *ipr;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipr = ELEMENT_DATA(e); 
		if (ROUTE_ISEQ(ipr, iproute)) {
			ipr->set = iproute->set;
			return 1;
		}
	}
	return 0;
}

/* Clear diff routes */
void
clear_diff_routes(list l, list n)
{
	ip_route_t *iproute;
	char *tmp_str;
	element e;

	/* No route in previous conf */
	if (LIST_ISEMPTY(l))
		return;

	/* All Static routes removed */
	if (LIST_ISEMPTY(n)) {
		log_message(LOG_INFO, "Removing a VirtualRoute block");
		netlink_rtlist(l, IPROUTE_DEL);
		return;
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		iproute = ELEMENT_DATA(e);
		if (!route_exist(n, iproute) && iproute->set) {
			tmp_str = ipaddresstos(iproute->dst);
			log_message(LOG_INFO, "ip route %s/%d ... , no longer exist"
					    , tmp_str, iproute->dmask);
			FREE(tmp_str);
			netlink_route(iproute, IPROUTE_DEL);
		}
	}
}

/* Diff conf handler */
void
clear_diff_sroutes(void)
{
	clear_diff_routes(old_vrrp_data->static_routes, vrrp_data->static_routes);
}
