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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <linux/icmpv6.h>
#include <inttypes.h>
#if HAVE_DECL_RTA_ENCAP
#include <linux/lwtunnel.h>
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
#include <linux/mpls_iptunnel.h>
#endif
#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
#include <linux/ila.h>
#endif
#endif
#include <stdbool.h>
#include <stdio.h>
#ifdef RTNETLINK_H_NEEDS_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <linux/rtnetlink.h>

/* local include */
#include "vrrp_iproute.h"
#include "keepalived_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "rttables.h"
#include "vrrp_ip_rule_route_parser.h"
#include "parser.h"

/* Buffer sizes for netlink messages. Increase if needed. */
#if 0
#define	RTM_SIZE		1024
#define	RTA_SIZE		1024
#define	ENCAP_RTA_SIZE		 128
#endif

/* Utility functions */
unsigned short
add_addr2req(struct nlmsghdr *n, size_t maxlen, unsigned short type, ip_address_t *ip_address)
{
	void *addr;
	size_t alen;

	if (!ip_address)
		return 0;

	if (IP_IS6(ip_address)) {
		addr = (void *) &ip_address->u.sin6_addr;
		alen = sizeof(ip_address->u.sin6_addr);
	}
	else
	{
	     addr = (void *) &ip_address->u.sin.sin_addr;
	     alen = sizeof(ip_address->u.sin.sin_addr);
	}

	return (unsigned short)addattr_l(n, maxlen, type, addr, alen);
}

#if 0
#if HAVE_DECL_RTA_VIA
static unsigned short
add_addr_fam2req(struct nlmsghdr *n, size_t maxlen, unsigned short type, ip_address_t *ip_address)
{
	void *addr;
	size_t alen;
	uint16_t family;

	if (!ip_address)
		return 0;

	if (IP_IS6(ip_address)) {
		addr = (void *)&ip_address->u.sin6_addr;
		alen = sizeof(ip_address->u.sin6_addr);
	}
	else {
		addr = (void *)&ip_address->u.sin.sin_addr;
		alen = sizeof(ip_address->u.sin.sin_addr);
	}
	family = ip_address->ifa.ifa_family;

	return (unsigned short)addattr_l2(n, maxlen, type, &family, sizeof(family), addr, alen);
}
#endif

static unsigned short
add_addr2rta(struct rtattr *rta, size_t maxlen, unsigned short type, ip_address_t *ip_address)
{
	void *addr;
	size_t alen;

	if (!ip_address)
		return 0;

	if (IP_IS6(ip_address)) {
		addr = (void *)&ip_address->u.sin6_addr;
		alen = sizeof(ip_address->u.sin6_addr);
	}
	else {
		addr = (void *)&ip_address->u.sin.sin_addr;
		alen = sizeof(ip_address->u.sin.sin_addr);
	}

	return (unsigned short)rta_addattr_l(rta, maxlen, type, addr, alen);
}

#if HAVE_DECL_RTA_VIA
static unsigned short
add_addrfam2rta(struct rtattr *rta, size_t maxlen, unsigned short type, ip_address_t *ip_address)
{
	void *addr;
	size_t alen;
	uint16_t family;

	if (!ip_address)
		return 0;

	if (IP_IS6(ip_address)) {
		addr = (void *)&ip_address->u.sin6_addr;
		alen = sizeof(ip_address->u.sin6_addr);
	}
	else {
		addr = (void *)&ip_address->u.sin.sin_addr;
		alen = sizeof(ip_address->u.sin.sin_addr);
	}
	family = ip_address->ifa.ifa_family;

	return (unsigned short)rta_addattr_l2(rta, maxlen, type, &family, sizeof(family), addr, alen);
}
#endif

#if HAVE_DECL_RTA_ENCAP
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
static void
add_encap_mpls(struct rtattr *rta, size_t len, const encap_t *encap)
{
	rta_addattr_l(rta, len, MPLS_IPTUNNEL_DST, &encap->mpls.addr, encap->mpls.num_labels * sizeof(encap->mpls.addr[0]));
}
#endif

static void
add_encap_ip(struct rtattr *rta, size_t len, const encap_t *encap)
{
	if (encap->flags & IPROUTE_BIT_ENCAP_ID)
		rta_addattr64(rta, len, LWTUNNEL_IP_ID, htobe64(encap->ip.id));
	if (encap->ip.dst)
		rta_addattr_l(rta, len, LWTUNNEL_IP_DST, &encap->ip.dst->u.sin.sin_addr.s_addr, sizeof(encap->ip.dst->u.sin.sin_addr.s_addr));
	if (encap->ip.src)
		rta_addattr_l(rta, len, LWTUNNEL_IP_SRC, &encap->ip.src->u.sin.sin_addr.s_addr, sizeof(encap->ip.src->u.sin.sin_addr.s_addr));
	if (encap->flags & IPROUTE_BIT_ENCAP_DSFIELD)
		rta_addattr8(rta, len, LWTUNNEL_IP_TOS, encap->ip.tos);
	if (encap->flags & IPROUTE_BIT_ENCAP_HOPLIMIT)
		rta_addattr8(rta, len, LWTUNNEL_IP_TTL, encap->ip.ttl);
	if (encap->flags & IPROUTE_BIT_ENCAP_FLAGS)
		rta_addattr16(rta, len, LWTUNNEL_IP_FLAGS, encap->ip.flags);
}

#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
static void
add_encap_ila(struct rtattr *rta, size_t len, const encap_t *encap)
{
	rta_addattr64(rta, len, ILA_ATTR_LOCATOR, encap->ila.locator);
}
#endif

static void
add_encap_ip6(struct rtattr *rta, size_t len, const encap_t *encap)
{
	if (encap->flags & IPROUTE_BIT_ENCAP_ID)
		rta_addattr64(rta, len, LWTUNNEL_IP6_ID, htobe64(encap->ip6.id));
	if (encap->ip6.dst)
		rta_addattr_l(rta, len, LWTUNNEL_IP6_DST, &encap->ip6.dst->u.sin6_addr, sizeof(encap->ip6.dst->u.sin6_addr));
	if (encap->ip6.src)
		rta_addattr_l(rta, len, LWTUNNEL_IP6_SRC, &encap->ip6.src->u.sin6_addr, sizeof(encap->ip6.src->u.sin6_addr));
	if (encap->flags & IPROUTE_BIT_ENCAP_DSFIELD)
		rta_addattr8(rta, len, LWTUNNEL_IP6_TC, encap->ip6.tc);
	if (encap->flags & IPROUTE_BIT_ENCAP_HOPLIMIT)
		rta_addattr8(rta, len, LWTUNNEL_IP6_HOPLIMIT, encap->ip6.hoplimit);
	if (encap->flags & IPROUTE_BIT_ENCAP_FLAGS)
		rta_addattr16(rta, len, LWTUNNEL_IP6_FLAGS, encap->ip6.flags);
}

static bool
add_encap(struct rtattr *rta, size_t len, encap_t *encap)
{
	struct rtattr *nest;

	nest = rta_nest(rta, len, RTA_ENCAP);
	switch (encap->type) {
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
	case LWTUNNEL_ENCAP_MPLS:
		add_encap_mpls(rta, len, encap);
		break;
#endif
	case LWTUNNEL_ENCAP_IP:
		add_encap_ip(rta, len, encap);
		break;
#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
	case LWTUNNEL_ENCAP_ILA:
		add_encap_ila(rta, len, encap);
		break;
#endif
	case LWTUNNEL_ENCAP_IP6:
		add_encap_ip6(rta, len, encap);
		break;
	default:
		log_message(LOG_INFO, "unknown encap type %d", encap->type);
		break;
	}
	rta_nest_end(rta, nest);

	rta_addattr16(rta, len, RTA_ENCAP_TYPE, encap->type);

	return true;
}
#endif

static void
add_nexthop(nexthop_t *nh, struct rtmsg *rtm, struct rtattr *rta, size_t len, struct rtnexthop *rtnh)
{
	if (nh->addr) {
		if (rtm->rtm_family == nh->addr->ifa.ifa_family)
			rtnh->rtnh_len = (unsigned short)(rtnh->rtnh_len + add_addr2rta(rta, len, RTA_GATEWAY, nh->addr));
#if HAVE_DECL_RTA_VIA
		else
			rtnh->rtnh_len = (unsigned short)(rtnh->rtnh_len + add_addrfam2rta(rta, len, RTA_VIA, nh->addr));
#endif
	}
	if (nh->ifp)
		rtnh->rtnh_ifindex = (int)nh->ifp->ifindex;

	if (nh->mask & IPROUTE_BIT_WEIGHT)
		rtnh->rtnh_hops = nh->weight;

	rtnh->rtnh_flags = nh->flags;

	if (nh->realms)
		rtnh->rtnh_len = (unsigned short)(rtnh->rtnh_len + rta_addattr32(rta, len, RTA_FLOW, nh->realms));

#if HAVE_DECL_RTA_ENCAP
	if (nh->encap.type != LWTUNNEL_ENCAP_NONE) {
		unsigned short rta_len = rta->rta_len;
		add_encap(rta, rta_len, &nh->encap);
		rtnh->rtnh_len = (unsigned short)(rtnh->rtnh_len + rta->rta_len - rta_len);
	}
#endif
}

static void
add_nexthops(ip_route_t *route, struct nlmsghdr *nlh, struct rtmsg *rtm)
{
	char buf[ENCAP_RTA_SIZE];
	struct rtattr *rta = (void *)buf;
	struct rtnexthop *rtnh;
	nexthop_t *nh;
	element e;

	rta->rta_type = RTA_MULTIPATH;
	rta->rta_len = RTA_LENGTH(0);
	rtnh = RTA_DATA(rta);

	for (e = LIST_HEAD(route->nhs); e; ELEMENT_NEXT(e)) {
		nh = ELEMENT_DATA(e);

		memset(rtnh, 0, sizeof(*rtnh));
		rtnh->rtnh_len = sizeof(*rtnh);
		rta->rta_len = (unsigned short)(rta->rta_len + rtnh->rtnh_len);
		add_nexthop(nh, rtm, rta, sizeof(buf), rtnh);
		rtnh = RTNH_NEXT(rtnh);
	}

	if (rta->rta_len > RTA_LENGTH(0))
		addattr_l(nlh, sizeof(buf), RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
}
#endif
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

static void dpvs_fill_rt4conf(ip_route_t *iproute, struct dp_vs_route_conf *route_conf)
{
	route_conf->af = AF_INET;
	(route_conf->dst).in  = (iproute->dst->u).sin.sin_addr;
	route_conf->plen = iproute->dst->ifa.ifa_prefixlen;

	if (iproute->via){
		(route_conf->via).in = (iproute->via->u).sin.sin_addr;
	} else {
		(route_conf->via).in.s_addr = 0;
	}

	if (iproute->pref_src){
		(route_conf->src).in = (iproute->pref_src->u).sin.sin_addr;
	} else {
		(route_conf->src).in.s_addr = 0;
	}

	route_conf->scope = scope_n2dpvs(iproute->scope);
	strncpy(route_conf->ifname, iproute->ifname, sizeof(route_conf->ifname));
	route_conf->mtu = 0;
	route_conf->metric = 0;
}

static void dpvs_fill_rt6conf(ip_route_t *iproute, struct dp_vs_route6_conf *rt6_cfg) 
{
	rt6_cfg->dst.addr = ((iproute->dst)->u).sin6_addr;
	rt6_cfg->dst.plen = iproute->dst->ifa.ifa_prefixlen;
	rt6_cfg->src.plen = 128;
	if (iproute->via) {
		rt6_cfg->gateway = (iproute->via->u).sin6_addr;
	} else {
		memset(&rt6_cfg->gateway, 0, sizeof(rt6_cfg->gateway));
	}

	if (iproute->pref_src) {
		rt6_cfg->src.addr = (iproute->pref_src->u).sin6_addr;
	} else {
		memset(&rt6_cfg->src, 0, sizeof(rt6_cfg->src));
	}

	rt6_cfg->flags |= flag_n2dpvs(iproute->scope);
	strncpy(rt6_cfg->ifname, iproute->ifname, sizeof(rt6_cfg->ifname));
	rt6_cfg->mtu = 0;
}

static int
netlink_route(ip_route_t *iproute, int cmd)
{
	int ret;
	if (iproute->dst->ifa.ifa_family == AF_INET) {
		struct dp_vs_route_conf *route_conf;
		route_conf = (struct dp_vs_route_conf *)malloc(sizeof(struct dp_vs_route_conf));
		memset(route_conf, 0, sizeof(*route_conf));
		dpvs_fill_rt4conf(iproute, route_conf);
		ret = ipvs_set_route(route_conf, cmd);
		free(route_conf);
	} else {
		struct dp_vs_route6_conf *rt6_cfg;
		rt6_cfg = (struct dp_vs_route6_conf *)malloc(sizeof(struct dp_vs_route6_conf));
		memset(rt6_cfg, 0, sizeof(*rt6_cfg));
		dpvs_fill_rt6conf(iproute, rt6_cfg);
		ret = ipvs_set_route6(rt6_cfg, cmd);
		free(rt6_cfg);
	}
	return ret;
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

	LIST_FOREACH(rt_list, iproute, e) {
		if ((cmd == IPROUTE_DEL) == iproute->set) {
			if (!netlink_route(iproute, cmd))
				iproute->set = (cmd == IPROUTE_ADD);
			else
				iproute->set = false;
		}
	}
}

/* Route dump/allocation */
static void
free_nh(void *rt_data)
{
	nexthop_t *nh = rt_data;

	FREE_PTR(nh->addr);
//#if HAVE_DECL_RTA_NEWDST
//	FREE_PTR(nh->as_to);
//#endif
	FREE(rt_data);
}

void
free_iproute(void *rt_data)
{
	ip_route_t *route = rt_data;

	FREE_PTR(route->dst);
	FREE_PTR(route->src);
	FREE_PTR(route->pref_src);
	FREE_PTR(route->via);
	free_list(&route->nhs);
#if HAVE_DECL_RTAX_CC_ALGO
	FREE_PTR(route->congctl);
#endif
	FREE(rt_data);
}

#if HAVE_DECL_RTA_ENCAP
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
static size_t
print_encap_mpls(char *op, size_t len, const encap_t* encap)
{
	char *buf = op;
	const char* buf_end = op + len;
	unsigned i;

	op += snprintf(op, (size_t)(buf_end - op), " encap mpls");
	for (i = 0; i < encap->mpls.num_labels; i++)
		op += snprintf(op, (size_t)(buf_end - op), "%s%x", i ? "/" : " ", ntohl(encap->mpls.addr[i].entry));

	return (size_t)(op - buf);
}
#endif

static size_t
print_encap_ip(char *op, size_t len, const encap_t* encap)
{
	char *buf = op;
	const char *buf_end = op + len;

	op += snprintf(op, (size_t)(buf_end - op), " encap ip");

	if (encap->flags & IPROUTE_BIT_ENCAP_ID)
		op += snprintf(op, (size_t)(buf_end - op), " id %" PRIu64, encap->ip.id);
	if (encap->ip.dst)
		op += snprintf(op, (size_t)(buf_end - op), " dst %s", ipaddresstos(NULL, encap->ip.dst));
	if (encap->ip.src)
		op += snprintf(op, (size_t)(buf_end - op), " src %s", ipaddresstos(NULL, encap->ip.src));
	if (encap->flags & IPROUTE_BIT_ENCAP_DSFIELD)
		op += snprintf(op, (size_t)(buf_end - op), " tos %d", encap->ip.tos);
	if (encap->flags & IPROUTE_BIT_ENCAP_TTL)
		op += snprintf(op, (size_t)(buf_end - op), " ttl %d", encap->ip.ttl);
	if (encap->flags & IPROUTE_BIT_ENCAP_FLAGS)
		op += snprintf(op, (size_t)(buf_end - op), " flags 0x%x", encap->ip.flags);

	return (size_t)(op - buf);
}

#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
static size_t
print_encap_ila(char *op, size_t len, const encap_t* encap)
{
	return (size_t)snprintf(op, len, " encap ila %" PRIu64, encap->ila.locator);
}
#endif

static size_t
print_encap_ip6(char *op, size_t len, const encap_t* encap)
{
	char *buf = op;
	const char *buf_end = op + len;

	op += snprintf(op, (size_t)(buf_end - op), " encap ip6");

	if (encap->flags & IPROUTE_BIT_ENCAP_ID)
		op += snprintf(op, (size_t)(buf_end - op), " id %" PRIu64, encap->ip6.id);
	if (encap->ip.dst)
		op += snprintf(op, (size_t)(buf_end - op), " dst %s", ipaddresstos(NULL, encap->ip6.dst));
	if (encap->ip.src)
		op += snprintf(op, (size_t)(buf_end - op), " src %s", ipaddresstos(NULL, encap->ip6.src));
	if (encap->flags & IPROUTE_BIT_ENCAP_DSFIELD)
		op += snprintf(op, (size_t)(buf_end - op), " tc %d", encap->ip6.tc);
	if (encap->flags & IPROUTE_BIT_ENCAP_HOPLIMIT)
		op += snprintf(op, (size_t)(buf_end - op), " hoplimit %d", encap->ip6.hoplimit);
	if (encap->flags & IPROUTE_BIT_ENCAP_FLAGS)
		op += snprintf(op, (size_t)(buf_end - op), " flags 0x%x", encap->ip6.flags);

	return (size_t)(op - buf);
}

static size_t
print_encap(char *op, size_t len, const encap_t* encap)
{
	switch (encap->type) {
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
	case LWTUNNEL_ENCAP_MPLS:
		return print_encap_mpls(op, len, encap);
#endif
	case LWTUNNEL_ENCAP_IP:
		return print_encap_ip(op, len, encap);
#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
	case LWTUNNEL_ENCAP_ILA:
		return print_encap_ila(op, len, encap);
#endif
	case LWTUNNEL_ENCAP_IP6:
		return print_encap_ip6(op, len, encap);
	}

	return (size_t)snprintf(op, len, "unknown encap type %d", encap->type);
}
#endif

void
format_iproute(const ip_route_t *route, char *buf, size_t buf_len)
{
	char *op = buf;
	const char *buf_end = buf + buf_len;
	nexthop_t *nh;
	interface_t *ifp;
	element e;

	if (route->type != RTN_UNICAST)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), "%s ", get_rttables_rtntype(route->type));
	if (route->dst)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), "%s", ipaddresstos(NULL, route->dst));
	else
		op += (size_t)snprintf(op, (size_t)(buf_end - op), "%s", "default");

	if (route->src)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " from %s", ipaddresstos(NULL, route->src));

//#if HAVE_DECL_RTA_NEWDST
//	/* MPLS only */
//	if (route->as_to)
//		op += (size_t)snprintf(op, (size_t)(buf_end - op), " as to %s", ipaddresstos(NULL, route->as_to));
//#endif

	if (route->pref_src)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " src %s", ipaddresstos(NULL, route->pref_src));

	if (route->mask & IPROUTE_BIT_DSFIELD)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " tos %u", route->tos);

#if HAVE_DECL_RTA_ENCAP
	if (route->encap.type != LWTUNNEL_ENCAP_NONE)
		op += print_encap(op, (size_t)(buf_end - op), &route->encap);
#endif

	if (route->via)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " via %s %s", route->via->ifa.ifa_family == AF_INET6 ? "inet6" : "inet", ipaddresstos(NULL, route->via));

	if (route->ifname[0])
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " dev %s", route->ifname);

	if (route->table != RT_TABLE_MAIN)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " table %u", route->table);

	if (route->mask & IPROUTE_BIT_PROTOCOL)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " proto %u", route->protocol);

	if (route->mask & IPROUTE_BIT_SCOPE)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " scope %u", route->scope);

	if (route->mask & IPROUTE_BIT_METRIC)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " metric %u", route->metric);

	if (route->family == AF_INET && route->flags & RTNH_F_ONLINK)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s", "onlink");

	if (route->realms) {
		if (route->realms & 0xFFFF0000)
			op += (size_t)snprintf(op, (size_t)(buf_end - op), " realms %" PRIu32 "/", route->realms >> 16);
		else
			op += (size_t)snprintf(op, (size_t)(buf_end - op), " realm ");
		op += (size_t)snprintf(op, (size_t)(buf_end - op), "%u", route->realms & 0xFFFF);
	}

#if HAVE_DECL_RTA_EXPIRES
	if (route->mask & IPROUTE_BIT_EXPIRES)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " expires %" PRIu32 "sec", route->expires);
#endif

#if HAVE_DECL_RTAX_CC_ALGO
	if (route->congctl)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " congctl %s%s", route->congctl, route->lock & (1<<RTAX_CC_ALGO) ? "lock " : "");
#endif

	if (route->mask & IPROUTE_BIT_RTT) {
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s%s ", "rtt", route->lock & (1<<RTAX_RTT) ? " lock" : "");
		if (route->rtt >= 8000)
			op += (size_t)snprintf(op, (size_t)(buf_end - op), "%gs", route->rtt / (double)8000.0F);
		else
			op += (size_t)snprintf(op, (size_t)(buf_end - op), "%ums", route->rtt / 8);
	}

	if (route->mask & IPROUTE_BIT_RTTVAR) {
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s%s ", "rttvar", route->lock & (1<<RTAX_RTTVAR) ? " lock" : "");
		if (route->rttvar >= 4000)
			op += (size_t)snprintf(op, (size_t)(buf_end - op), "%gs", route->rttvar / (double)4000.0F);
		else
			op += (size_t)snprintf(op, (size_t)(buf_end - op), "%ums", route->rttvar / 4);
	}

	if (route->mask & IPROUTE_BIT_RTO_MIN) {
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s%s ", "rto_min", route->lock & (1<<RTAX_RTO_MIN) ? " lock" : "");
		if (route->rto_min >= 1000)
			op += (size_t)snprintf(op, (size_t)(buf_end - op), "%gs", route->rto_min / (double)1000.0F);
		else
			op += (size_t)snprintf(op, (size_t)(buf_end - op), "%ums", route->rto_min);
	}

	if (route->features) {
		if (route->features & RTAX_FEATURE_ECN)
			op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s", "features ecn");
	}

	if (route->mask & IPROUTE_BIT_MTU) {
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " mtu %s%u",
			route->lock & (1<<RTAX_MTU) ? "lock " : "",
			route->mtu);
	}

	if (route->mask & IPROUTE_BIT_WINDOW)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " window %u", route->window);

	if (route->mask & IPROUTE_BIT_SSTHRESH) {
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " ssthresh %s%u",
			route->lock & (1<<RTAX_SSTHRESH) ? "lock " : "",
			route->ssthresh);
	}

	if (route->mask & IPROUTE_BIT_CWND) {
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " cwnd %s%u",
			route->lock & (1<<RTAX_CWND) ? "lock " : "",
			route->cwnd);
	}

	if (route->mask & IPROUTE_BIT_ADVMSS) {
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " advmss %s%u",
			route->lock & (1<<RTAX_ADVMSS) ? "lock " : "",
			route->advmss);
	}

	if (route->mask & IPROUTE_BIT_REORDERING) {
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " reordering %s%u",
			route->lock & (1<<RTAX_REORDERING) ? "lock " : "",
			route->reordering);
	}

	if (route->mask & IPROUTE_BIT_HOPLIMIT)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " hoplimit %u", route->hoplimit);

	if (route->mask & IPROUTE_BIT_INITCWND)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " initcwnd %u", route->initcwnd);

	if (route->mask & IPROUTE_BIT_INITRWND)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " initrwnd %u", route->initrwnd);

#if HAVE_DECL_RTAX_QUICKACK
	if (route->mask & IPROUTE_BIT_QUICKACK)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " quickack %d", route->quickack);
#endif

#if HAVE_DECL_RTA_PREF
	if (route->mask & IPROUTE_BIT_PREF)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s %s", "pref",
			route->pref == ICMPV6_ROUTER_PREF_LOW ? "low" :
			route->pref == ICMPV6_ROUTER_PREF_MEDIUM ? "medium" :
			route->pref == ICMPV6_ROUTER_PREF_HIGH ? "high" :
			"unknown");
#endif

#if HAVE_DECL_RTAX_FASTOPEN_NO_COOKIE
	if (route->mask & IPROUTE_BIT_FASTOPEN_NO_COOKIE)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s %d", "fastopen_no_cookie", route->fastopen_no_cookie);
#endif

#if HAVE_DECL_RTA_TTL_PROPAGATE
	if (route->mask & IPROUTE_BIT_TTL_PROPAGATE)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " %s %sabled", "ttl-propagate", route->ttl_propagate ? "en" : "dis");
#endif

	if (!LIST_ISEMPTY(route->nhs)) {
		for (e = LIST_HEAD(route->nhs); e; ELEMENT_NEXT(e)) {
			nh = ELEMENT_DATA(e);

			op += (size_t)snprintf(op, (size_t)(buf_end - op), " nexthop");

			if (nh->addr)
				op += (size_t)snprintf(op, (size_t)(buf_end - op), " via inet%s %s",
					nh->addr->ifa.ifa_family == AF_INET ? "" : "6",
					ipaddresstos(NULL,nh->addr));
			if (nh->ifp)
				op += (size_t)snprintf(op, (size_t)(buf_end - op), " dev %s", nh->ifp->ifname);

			if (nh->mask & IPROUTE_BIT_WEIGHT)
				op += (size_t)snprintf(op, (size_t)(buf_end - op), " weight %d", nh->weight + 1);

			if (nh->flags & RTNH_F_ONLINK)
				op += (size_t)snprintf(op, (size_t)(buf_end - op), " onlink");

			if (nh->realms) {
				if (route->realms & 0xFFFF0000)
					op += (size_t)snprintf(op, (size_t)(buf_end - op), " realms %" PRIu32 "/", nh->realms >> 16);
				else
					op += (size_t)snprintf(op, (size_t)(buf_end - op), " realm ");
				op += (size_t)snprintf(op, (size_t)(buf_end - op), "%" PRIu32, nh->realms & 0xFFFF);
			}
#if HAVE_DECL_RTA_ENCAP
			if (nh->encap.type != LWTUNNEL_ENCAP_NONE)
				op += print_encap(op, (size_t)(buf_end - op), &nh->encap);
#endif
		}
	}

	if (route->dont_track)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " no_track");

	if (route->track_group)
		op += (size_t)snprintf(op, (size_t)(buf_end - op), " track_group %s", route->track_group->gname);

#if 0
	if (route->set &&
	    !route->dont_track &&
	    (!route->oif || route->oif->ifindex != route->configured_ifindex)) {
		if ((ifp = if_get_by_ifindex(route->configured_ifindex)))
			op += (size_t)snprintf(op, (size_t)(buf_end - op), " [dev %s]", ifp->ifname);
		else
			op += (size_t)snprintf(op, (size_t)(buf_end - op), " [installed ifindex %" PRIu32 "]", route->configured_ifindex);
	}
#endif
}

void
dump_iproute(FILE *fp, const void *rt_data)
{
	const ip_route_t *route = rt_data;
	char *buf = MALLOC(ROUTE_BUF_SIZE);
	size_t len;
	size_t i;

	format_iproute(route, buf, ROUTE_BUF_SIZE);

	if (fp)
		conf_write(fp, "%*s%s", 5, "", buf);
	else {
		for (i = 0, len = strlen(buf); i < len; i += i ? MAX_LOG_MSG - 7 : MAX_LOG_MSG - 5)
			conf_write(fp, "%*s%s", i ? 6 : 5, "", buf + i);
	}

	FREE(buf);
}

#if HAVE_DECL_RTA_ENCAP
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
static int parse_encap_mpls(const vector_t *strvec, unsigned int *i_ptr, encap_t *encap)
{
	const char *str;

	encap->type = LWTUNNEL_ENCAP_MPLS;

	if (*i_ptr >= vector_size(strvec)) {
		report_config_error(CONFIG_GENERAL_ERROR, "missing address for MPLS encapsulation");
		return true;
	}

	str = strvec_slot(strvec, (*i_ptr)++);
	if (parse_mpls_address(str, &encap->mpls)) {
		report_config_error(CONFIG_GENERAL_ERROR, "invalid mpls address %s for encapsulation", str);
		return true;
	}

	return false;
}
#endif

static int parse_encap_ip(const vector_t *strvec, unsigned int *i_ptr, encap_t *encap)
{
	unsigned int i = *i_ptr;
	const char *str, *str1;

	encap->type = LWTUNNEL_ENCAP_IP;

	while (i + 1 < vector_size(strvec)) {
		str = strvec_slot(strvec, i);
		str1 = strvec_slot(strvec, i + 1);

		if (!strcmp(str, "id")) {
			if (get_u64(&encap->ip.id, str1, UINT64_MAX, "encap id %s value is invalid"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_ID;
		} else if (!strcmp(str, "dst")) {
			if (encap->ip.dst)
				FREE_PTR(encap->ip.dst);
			encap->ip.dst = parse_ipaddress(NULL, str1, false);
			if (!encap->ip.dst) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid encap ip dst %s", str1);
				goto err;
			}
			if (encap->ip.dst->ifa.ifa_family != AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "IPv6 address %s not valid for ip encapsulation", str1);
				goto err;
			}
		} else if (!strcmp(str, "src")) {
			if (encap->ip.src)
				FREE_PTR(encap->ip.src);
			encap->ip.src = parse_ipaddress(NULL, str1, false);
			if (!encap->ip.src) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid encap ip src %s", str1);
				goto err;
			}
			if (encap->ip.src->ifa.ifa_family != AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "IPv6 address %s not valid for ip encapsulation", str1);
				goto err;
			}
		} else if (!strcmp(str, "tos")) {
			if (!find_rttables_dsfield(str1, &encap->ip.tos)) {
				report_config_error(CONFIG_GENERAL_ERROR, "dsfield %s not valid for ip encapsulation", str1);
				goto err;
			}
			encap->flags |= IPROUTE_BIT_ENCAP_DSFIELD;
		} else if (!strcmp(str, "ttl")) {
			if (get_u8(&encap->ip.ttl, str1, UINT8_MAX, "ttl %s is not valid for ip encapsulation"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_TTL;
		} else if (!strcmp(str, "flags")) {
			if (get_u16(&encap->ip.flags, str1, UINT16_MAX, "flags %s is not valid for ip encapsulation"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_FLAGS;
		} else
			break;

		i += 2;
	}

	if (!encap->ip.dst && !(encap->flags & IPROUTE_BIT_ENCAP_ID)) {
		report_config_error(CONFIG_GENERAL_ERROR, "address or id missing for ip encapsulation");
		goto err;
	}

	*i_ptr = i;

	return false;

err:
	*i_ptr = i;

	if (encap->ip.dst) {
		FREE_PTR(encap->ip.dst);
		encap->ip.dst = NULL;
	}
	if (encap->ip.src){
		FREE_PTR(encap->ip.src);
		encap->ip.src = NULL;
	}

	return true;
}

#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
static
int parse_encap_ila(const vector_t *strvec, unsigned int *i_ptr, encap_t *encap)
{
	const char *str;

	encap->type = LWTUNNEL_ENCAP_ILA;

	if (*i_ptr >= vector_size(strvec)) {
		report_config_error(CONFIG_GENERAL_ERROR, "missing locator for ILA encapsulation");
		return true;
	}

	str = strvec_slot(strvec, (*i_ptr)++);

	if (get_addr64(&encap->ila.locator, str)) {
		report_config_error(CONFIG_GENERAL_ERROR, "invalid locator %s for ila encapsulation", str);
		return true;
	}

	return false;
}
#endif

static
int parse_encap_ip6(const vector_t *strvec, unsigned int *i_ptr, encap_t *encap)
{
	unsigned int i = *i_ptr;
	const char *str, *str1;

	encap->type = LWTUNNEL_ENCAP_IP6;

	while (i + 1 < vector_size(strvec)) {
		str = strvec_slot(strvec, i);
		str1 = strvec_slot(strvec, i + 1);

		if (!strcmp(str, "id")) {
			if (get_u64(&encap->ip6.id, str1, UINT64_MAX, "id %s value invalid for IPv6 encapsulation"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_ID;
		} else if (!strcmp(str, "dst")) {
			if (encap->ip6.dst)
				FREE_PTR(encap->ip6.dst);
			encap->ip6.dst = parse_ipaddress(NULL, str1, false);
			if (!encap->ip6.dst) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid encap ip6 dst %s", str1);
				goto err;
			}
			if (encap->ip6.dst->ifa.ifa_family != AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "IPv4 address %s not valid for ip6 encapsulation", str1);
				goto err;
			}
		} else if (!strcmp(str, "src")) {
			if (encap->ip6.src)
				FREE_PTR(encap->ip6.src);
			encap->ip6.src = parse_ipaddress(NULL, str1, false);
			if (!encap->ip6.src) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid encap ip6 src %s", str1);
				goto err;
			}
			if (encap->ip6.src->ifa.ifa_family != AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "IPv4 address %s not valid for ip6 encapsulation", str1);
				goto err;
			}
		} else if (!strcmp(str, "tc")) {
			if (!find_rttables_dsfield(str1, &encap->ip6.tc)) {
				report_config_error(CONFIG_GENERAL_ERROR, "tc value %s is invalid for ip6 encapsulation", str);
				goto err;
			}
			encap->flags |= IPROUTE_BIT_ENCAP_DSFIELD;
		} else if (!strcmp(str, "hoplimit")) {
			if (get_u8(&encap->ip6.hoplimit, str1, UINT8_MAX, "Invalid hoplimit %s specified for ip6 encapsulation"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_HOPLIMIT;
		} else if (!strcmp(str, "flags")) {
			if (get_u16(&encap->ip6.flags, str1, UINT16_MAX, "flags %s is not valid for ip6 encapsulation"))
				goto err;
			encap->flags |= IPROUTE_BIT_ENCAP_FLAGS;
		} else
			break;

		i += 2;
	}

	if (!encap->ip.dst && !(encap->flags & IPROUTE_BIT_ENCAP_ID)) {
		report_config_error(CONFIG_GENERAL_ERROR, "address or id missing for ip6 encapsulation");
		goto err;
	}

	*i_ptr = i;
	return false;

err:
	*i_ptr = i;
	if (encap->ip6.dst) {
		FREE_PTR(encap->ip6.dst);
		encap->ip6.dst = NULL;
	}
	if (encap->ip6.src) {
		FREE_PTR(encap->ip6.src);
		encap->ip6.src = NULL;
	}

	return true;
}

static bool
parse_encap(const vector_t *strvec, unsigned int *i, encap_t *encap)
{
	const char *str;

	if (vector_size(strvec) <= ++*i) {
		report_config_error(CONFIG_GENERAL_ERROR, "Missing encap type");
		return false;
	}

	str = strvec_slot(strvec, (*i)++);

	if (!strcmp(str, "ip"))
		parse_encap_ip(strvec, i, encap);
	else if (!strcmp(str, "ip6"))
		parse_encap_ip6(strvec, i, encap);
#if HAVE_DECL_LWTUNNEL_ENCAP_MPLS
	else if (!strcmp(str, "mpls"))
		parse_encap_mpls(strvec, i, encap);
#endif
#if HAVE_DECL_LWTUNNEL_ENCAP_ILA
	else if (!strcmp(str, "ila"))
		parse_encap_ila(strvec, i, encap);
#endif
	else {
		report_config_error(CONFIG_GENERAL_ERROR, "Unknown encap type - %s", str);
		return false;
	}

	--*i;
	return true;
}
#endif

static void
parse_nexthops(const vector_t *strvec, unsigned int i, ip_route_t *route)
{
	uint8_t family = AF_UNSPEC;
	nexthop_t *new;
	const char *str;
	uint32_t val;

	if (!LIST_EXISTS(route->nhs))
		route->nhs = alloc_list(free_nh, NULL);

	while (i < vector_size(strvec) && !strcmp("nexthop", strvec_slot(strvec, i))) {
		i++;
		new = MALLOC(sizeof(nexthop_t));

		while (i < vector_size(strvec)) {
			str = strvec_slot(strvec, i);

			if (!strcmp(str, "via")) {
				str = strvec_slot(strvec, ++i);
				if (!strcmp(str, "inet")) {
					family = AF_INET;
					str = strvec_slot(strvec, ++i);
				}
				else if (!strcmp(str, "inet6")) {
					family = AF_INET6;
					str = strvec_slot(strvec, ++i);
				}

				if (family != AF_UNSPEC) {
					if (route->family == AF_UNSPEC)
						route->family = family;
					else if (route->family != family) {
						report_config_error(CONFIG_GENERAL_ERROR, "IPv4/6 mismatch for nexthop");
						goto err;
					}
				}

				new->addr = parse_ipaddress(NULL, str, false);
				if (!new->addr) {
					report_config_error(CONFIG_GENERAL_ERROR, "invalid nexthop address %s", str);
					goto err;
				}
				if (route->family != AF_UNSPEC && new->addr->ifa.ifa_family != route->family) {
					report_config_error(CONFIG_GENERAL_ERROR, "Address family mismatch for next hop");
					goto err;
				}
				if (route->family == AF_UNSPEC)
					route->family = new->addr->ifa.ifa_family;
			}
			else if (!strcmp(str, "dev")) {
				str = strvec_slot(strvec, ++i);
				new->ifp = if_get_by_ifname(str, IF_CREATE_IF_DYNAMIC);
				if (!new->ifp) {
					report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s for VROUTE nexthop doesn't exist", str);
					goto err;
				}
			}
			else if (!strcmp(str, "weight")) {
				if (get_u32(&val, strvec_slot(strvec, ++i), 256, "Invalid weight %s specified for route"))
					goto err;
				if (!val) {
					report_config_error(CONFIG_GENERAL_ERROR, "Invalid weight 0 specified for route");
					goto err;
				}
				new->weight = (uint8_t)(--val & 0xff);
				new->mask |= IPROUTE_BIT_WEIGHT;
			}
			else if (!strcmp(str, "onlink")) {
				/* Note: IPv4 only */
				new->flags |= RTNH_F_ONLINK;
			}
			else if (!strcmp(str, "encap")) {	// New in 4.4
#if HAVE_DECL_RTA_ENCAP
				parse_encap(strvec, &i, &new->encap);
#else
				report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "encap");
#endif
			}
			else if (!strcmp(str, "realms")) {
				/* Note: IPv4 only */
				if (get_realms(&new->realms, strvec_slot(strvec, ++i))) {
					report_config_error(CONFIG_GENERAL_ERROR, "Invalid realms %s for route", strvec_slot(strvec,i));
					goto err;
				}
				if (route->family == AF_UNSPEC)
					route->family = AF_INET;
				else if (route->family != AF_INET) {
					report_config_error(CONFIG_GENERAL_ERROR, "realms are only supported for IPv4");
					goto err;
				}
			}
			else if (!strcmp(str, "as")) {
				if (!strcmp("to", strvec_slot(strvec, ++i)))
					i++;
				report_config_error(CONFIG_GENERAL_ERROR, "'as [to]' (nat) not supported");
				goto err;
			}
			else
				break;

			i++;
		}
		list_add(route->nhs, new);
		new = NULL;
	}

	if (i < vector_size(strvec)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Route has trailing nonsense after nexthops - %s", strvec_slot(strvec, i));
		goto err;
	}

	return;

err:
	FREE_PTR(new);
}

void
alloc_route(list rt_list, const vector_t *strvec, bool allow_track_group)
{
	ip_route_t *new;
	const char *str;
	uint32_t val;
	uint8_t val8;
	unsigned int i = 0;
	bool do_nexthop = false;
	bool raw;
	uint8_t family;
	const char *dest = NULL;

	new = (ip_route_t *) MALLOC(sizeof(ip_route_t));

	new->table = RT_TABLE_MAIN;
	new->scope = RT_SCOPE_UNIVERSE;
	new->type = RTN_UNICAST;
	new->family = AF_UNSPEC;
	new->oif = NULL;
	memset(new->ifname, 0, sizeof(new->ifname));

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = strvec_slot(strvec, i);

		/* cmd parsing */
		if (!strcmp(str, "inet6")) {
			if (new->family == AF_UNSPEC)
				new->family = AF_INET6;
			else if (new->family != AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "inet6 specified for IPv4 route");
				goto err;
			}
			i++;
		}
		else if (!strcmp(str, "inet")) {
			if (new->family == AF_UNSPEC)
				new->family = AF_INET;
			else if (new->family != AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "inet specified for IPv6 route");
				goto err;
			}
			i++;
		}
		else if (!strcmp(str, "src")) {
			if (new->pref_src)
				FREE(new->pref_src);
			new->pref_src = parse_ipaddress(NULL, strvec_slot(strvec, ++i), false);
			if (!new->pref_src) {
				report_config_error(CONFIG_GENERAL_ERROR, "invalid route src address %s", strvec_slot(strvec, i));
				goto err;
			}
			if (new->family == AF_UNSPEC)
				new->family = new->pref_src->ifa.ifa_family;
			else if (new->family != new->pref_src->ifa.ifa_family) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot mix IPv4 and IPv6 addresses for route");
				goto err;
			}
		}
		else if (!strcmp(str, "as")) {
			if (!strcmp("to", strvec_slot(strvec, ++i)))
				i++;
#if HAVE_DECL_RTA_NEWDST
			report_config_error(CONFIG_GENERAL_ERROR, "\"as to\" for MPLS only - ignoring");
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "'as [to]'");
#endif
		}
		else if (!strcmp(str, "via") || !strcmp(str, "gw")) {

			/* "gw" maintained for backward keepalived compatibility */
			if (str[0] == 'g')	/* "gw" */
				report_config_error(CONFIG_GENERAL_ERROR, "\"gw\" for routes is deprecated. Please use \"via\"");

			str = strvec_slot(strvec, ++i);
			if (!strcmp(str, "inet")) {
				family = AF_INET;
				str = strvec_slot(strvec, ++i);
			}
			else if (!strcmp(str, "inet6")) {
				family = AF_INET6;
				str = strvec_slot(strvec, ++i);
			}
			else
				family = new->family;

			if (new->family == AF_UNSPEC)
				new->family = family;
			else if (new->family != family) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot mix IPv4 and IPv6 addresses for route");
				goto err;
			}

			if (new->via)
				FREE(new->via);
			new->via = parse_ipaddress(NULL, str, false);
			if (!new->via) {
				report_config_error(CONFIG_GENERAL_ERROR, "invalid route via address %s", strvec_slot(strvec, i));
				goto err;
			}
			if (new->family == AF_UNSPEC)
				new->family = new->via->ifa.ifa_family;
			else if (new->family != new->via->ifa.ifa_family) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot mix IPv4 and IPv6 addresses for route");
				goto err;
			}
		}
		else if (!strcmp(str, "from")) {
			if (new->src)
				FREE(new->src);
			new->src = parse_route(strvec_slot(strvec, ++i));
			if (!new->src) {
				report_config_error(CONFIG_GENERAL_ERROR, "invalid route from address %s", strvec_slot(strvec, i));
				goto err;
			}
			if (new->src->ifa.ifa_family != AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "route from address only supported with IPv6 (%s)", strvec_slot(strvec, i));
				goto err;
			}
			if (new->family == AF_UNSPEC)
				new->family = new->src->ifa.ifa_family;
			else if (new->family != new->src->ifa.ifa_family) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot mix IPv4 and IPv6 addresses for route");
				goto err;
			}
		}
		else if (!strcmp(str, "tos") || !strcmp(str,"dsfield")) {
			/* Note: IPv4 only */
			if (!find_rttables_dsfield(strvec_slot(strvec, ++i), &val8)) {
				report_config_error(CONFIG_GENERAL_ERROR, "TOS value %s is invalid", strvec_slot(strvec, i));
				goto err;
			}

			new->tos = val8;
			new->mask |= IPROUTE_BIT_DSFIELD;
		}
		else if (!strcmp(str, "table")) {
			if (!find_rttables_table(strvec_slot(strvec, ++i), &val)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Routing table %s not found for route", strvec_slot(strvec, i));
				goto err;
			}
			new->table = val;
		}
		else if (!strcmp(str, "protocol")) {
			if (!find_rttables_proto(strvec_slot(strvec, ++i), &val8)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Protocol %s not found or invalid for route", strvec_slot(strvec, i));
				goto err;
			}
			new->protocol = val8;
			new->mask |= IPROUTE_BIT_PROTOCOL;
		}
		else if (!strcmp(str, "scope")) {
			/* Note: IPv4 only */
			if (!find_rttables_scope(strvec_slot(strvec, ++i), &val8)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Scope %s not found or invalid for route", strvec_slot(strvec, i));
				goto err;
			}
			new->scope = val8;
			new->mask |= IPROUTE_BIT_SCOPE;
		}
		else if (!strcmp(str, "metric") ||
			 !strcmp(str, "priority") ||
			 !strcmp(str, "preference")) {
			if (get_u32(&new->metric, strvec_slot(strvec, ++i), UINT32_MAX, "Invalid metric %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_METRIC;
		}
		else if (!strcmp(str, "dev") || !strcmp(str, "oif")) {
			strcpy(new->ifname, strvec_slot(strvec, ++i));
		}
		else if (!strcmp(str, "onlink")) {
			/* Note: IPv4 only */
			new->flags |= RTNH_F_ONLINK;
		}
		else if (!strcmp(str, "encap")) {	// New in 4.4
#if HAVE_DECL_RTA_ENCAP
			parse_encap(strvec, &i, &new->encap);
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "encap");
#endif
		}
		else if (!strcmp(str, "expires")) {	// New in 4.4
			i++;
#if HAVE_DECL_RTA_EXPIRES
			if (new->family == AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "expires is only valid for IPv6");
				goto err;
			}
			new->family = AF_INET6;
			if (get_u32(&new->expires, strvec_slot(strvec, i), UINT32_MAX, "Invalid expires time %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_EXPIRES;
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "expires");
#endif
		}
		else if (!strcmp(str, "mtu")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_MTU;
				i++;
			}
			if (get_u32(&new->mtu, strvec_slot(strvec, i), UINT32_MAX, "Invalid MTU %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_MTU;
		}
		else if (!strcmp(str, "hoplimit")) {
			if (get_u8(&val8, strvec_slot(strvec, ++i), 255, "Invalid hoplimit %s specified for route"))
				goto err;
			new->hoplimit = val8;
			new->mask |= IPROUTE_BIT_HOPLIMIT;
		}
		else if (!strcmp(str, "advmss")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_ADVMSS;
				i++;
			}
			if (get_u32(&new->advmss, strvec_slot(strvec, i), UINT32_MAX, "Invalid advmss %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_ADVMSS;
		}
		else if (!strcmp(str, "rtt")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_RTT;
				i++;
			}
			if (get_time_rtt(&new->rtt, strvec_slot(strvec, i), &raw) ||
			    (!raw && new->rtt >= UINT32_MAX / 8)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rtt %s for route", strvec_slot(strvec,i));
				goto err;
			}
			if (raw)
				new->rtt *= 8;
			new->mask |= IPROUTE_BIT_RTT;
		}
		else if (!strcmp(str, "rttvar")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_RTTVAR;
				i++;
			}
			if (get_time_rtt(&new->rttvar, strvec_slot(strvec, i), &raw) ||
			    (!raw && new->rttvar >= UINT32_MAX / 4)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rttvar %s for route", strvec_slot(strvec,i));
				goto err;
			}
			if (raw)
				new->rttvar *= 4;
			new->mask |= IPROUTE_BIT_RTTVAR;
		}
		else if (!strcmp(str, "reordering")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_REORDERING;
				i++;
			}
			if (get_u32(&new->reordering, strvec_slot(strvec, i), UINT32_MAX, "Invalid reordering value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_REORDERING;
		}
		else if (!strcmp(str, "window")) {
			if (get_u32(&new->window, strvec_slot(strvec, ++i), UINT32_MAX, "Invalid window value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_WINDOW;
		}
		else if (!strcmp(str, "cwnd")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_CWND;
				i++;
			}
			if (get_u32(&new->cwnd, strvec_slot(strvec, i), UINT32_MAX, "Invalid cwnd value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_CWND;
		}
		else if (!strcmp(str, "ssthresh")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_SSTHRESH;
				i++;
			}
			if (get_u32(&new->ssthresh, strvec_slot(strvec, i), UINT32_MAX, "Invalid ssthresh value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_SSTHRESH;
		}
		else if (!strcmp(str, "realms")) {
			if (get_realms(&new->realms, strvec_slot(strvec, ++i))) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid realms %s for route", strvec_slot(strvec,i));
				goto err;
			}
			if (new->family == AF_INET6) {
				report_config_error(CONFIG_GENERAL_ERROR, "realms are only valid for IPv4");
				goto err;
			}
			new->family = AF_INET;
		}
		else if (!strcmp(str, "rto_min")) {
			if (!strcmp(strvec_slot(strvec, ++i), "lock")) {
				new->lock |= 1 << RTAX_RTO_MIN;
				i++;
			}
			if (get_time_rtt(&new->rto_min, strvec_slot(strvec, i), &raw)) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid rto_min value %s specified for route", strvec_slot(strvec, i));
				goto err;
			}
			new->mask |= IPROUTE_BIT_RTO_MIN;
		}
		else if (!strcmp(str, "initcwnd")) {
			if (get_u32(&new->initcwnd, strvec_slot(strvec, ++i), UINT32_MAX, "Invalid initcwnd value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_INITCWND;
		}
		else if (!strcmp(str, "initrwnd")) {
			i++;
			if (get_u32(&new->initrwnd, strvec_slot(strvec, i), UINT32_MAX, "Invalid initrwnd value %s specified for route"))
				goto err;
			new->mask |= IPROUTE_BIT_INITRWND;
		}
		else if (!strcmp(str, "features")) {
			i++;
			if (!strcmp("ecn", strvec_slot(strvec, i)))
				new->features |= RTAX_FEATURE_ECN;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "feature %s not supported", strvec_slot(strvec,i));
		}
		else if (!strcmp(str, "quickack")) {
			i++;
#if HAVE_DECL_RTAX_QUICKACK
			if (get_u32(&val, strvec_slot(strvec, i), 1, "Invalid quickack value %s specified for route"))
				goto err;
			new->quickack = val;
			new->mask |= IPROUTE_BIT_QUICKACK;
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "quickack for route");
#endif
		}
		else if (!strcmp(str, "congctl")) {
			i++;
#if HAVE_DECL_RTAX_CC_ALGO
			if (!strcmp(strvec_slot(strvec, i), "lock")) {
				new->lock |= 1 << RTAX_CC_ALGO;
				i++;
			}
			str = strvec_slot(strvec, i);
			new->congctl = malloc(strlen(str) + 1);
			strcpy(new->congctl, str);
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "congctl for route");
#endif
		}
		else if (!strcmp(str, "pref")) {
			i++;
#if HAVE_DECL_RTA_PREF
			if (new->family == AF_INET) {
				report_config_error(CONFIG_GENERAL_ERROR, "pref is only valid for IPv6");
				goto err;
			}
			new->family = AF_INET6;
			str = strvec_slot(strvec, i);
			if (!strcmp(str, "low"))
				new->pref = ICMPV6_ROUTER_PREF_LOW;
			else if (!strcmp(str, "medium"))
				new->pref = ICMPV6_ROUTER_PREF_MEDIUM;
			else if (!strcmp(str, "high"))
				new->pref = ICMPV6_ROUTER_PREF_HIGH;
			else if (!get_u8(&val8, str, UINT8_MAX, "Invalid pref value %s specified for route"))
				new->pref = val8;
			else
				goto err;
			new->mask |= IPROUTE_BIT_PREF;
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "pref");
#endif
		}
		else if (!strcmp(str, "ttl-propagate")) {
			i++;
#if HAVE_DECL_RTA_TTL_PROPAGATE
			str = strvec_slot(strvec, i);
			if (!strcmp(str, "enabled"))
				new->ttl_propagate = 1;
			else if (!strcmp(str, "disabled"))
				new->ttl_propagate = 0;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "%s value %s not recognised", "ttl-propagate", str);
			new->mask |= IPROUTE_BIT_TTL_PROPAGATE;
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "ttl-propagate");
#endif
		}
		else if (!strcmp(str, "fastopen_no_cookie")) {
			i++;
#if HAVE_DECL_RTAX_FASTOPEN_NO_COOKIE
			if (get_u32(&val, strvec_slot(strvec, i), 1, "Invalid fastopen_no_cookie value %s specified for route"))
				goto err;
			new->fastopen_no_cookie = !!val;
			new->mask |= IPROUTE_BIT_FASTOPEN_NO_COOKIE;
#else
			report_config_error(CONFIG_GENERAL_ERROR, "%s not supported by kernel", "fastopen_no_cookie");
#endif
		}
		/* Maintained for backward compatibility */
		else if (!strcmp(str, "or")) {
			report_config_error(CONFIG_GENERAL_ERROR, "\"or\" for routes is deprecated. Please use \"nexthop\"");

			if (new->nhs) {
				report_config_error(CONFIG_GENERAL_ERROR, "\"or\" route already specified - ignoring subsequent");
				i += 2;
				continue;
			}

			new->nhs = alloc_list(free_nh, NULL);

			/* Transfer the via address to the first nexthop */
			nexthop_t *nh = MALLOC(sizeof(nexthop_t));
			nh->addr = new->via;
			new->via = NULL;
			list_add(new->nhs, nh);

			/* Now handle the "or" address */
			nh = MALLOC(sizeof(nexthop_t));
			nh->addr = parse_ipaddress(NULL, strvec_slot(strvec, ++i), false);
			if (!nh->addr) {
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid \"or\" address %s", strvec_slot(strvec, i));
				FREE(nh);
				goto err;
			}
			list_add(new->nhs, nh);
		}
		else if (!strcmp(str, "nexthop")) {
			if (new->nhs)
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify nexthops with \"or\" route");
			else
				do_nexthop = true;
			break;
		}
		else if (!strcmp(str, "no_track"))
			new->dont_track = true;
		else if (allow_track_group && !strcmp(str, "track_group")) {
			i++;
			if (new->track_group) {
				report_config_error(CONFIG_GENERAL_ERROR, "track_group %s is a duplicate", strvec_slot(strvec, i));
				break;
			}
			if (!(new->track_group = find_track_group(strvec_slot(strvec, i))))
				report_config_error(CONFIG_GENERAL_ERROR, "track_group %s not found", strvec_slot(strvec, i));
		}
		else {
			if (!strcmp(str, "to"))
				i++;

			if (find_rttables_rtntype(str, &val8)) {
				new->type = val8;
				new->mask |= IPROUTE_BIT_TYPE;
				i++;
			}
			if (new->dst)
				FREE(new->dst);
			dest = strvec_slot(strvec, i);
			new->dst = parse_route(dest);
			if (!new->dst) {
				report_config_error(CONFIG_GENERAL_ERROR, "unknown route keyword %s", dest);
				goto err;
			}
			if (new->family == AF_UNSPEC)
				new->family = new->dst->ifa.ifa_family;
			else if (new->family != new->dst->ifa.ifa_family) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot mix IPv4 and IPv6 addresses for route (%s)", dest);
				goto err;
			}
		}
		i++;
	}

	if (do_nexthop)
		parse_nexthops(strvec, i, new);
	else if (i < vector_size(strvec)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Route has trailing nonsense - %s", strvec_slot(strvec, i));
		goto err;
	}

	if (!new->dst) {
		report_config_error(CONFIG_GENERAL_ERROR, "Route must have a destination");
		goto err;
	}

	if (!new->dont_track) {
		if ((new->mask & IPROUTE_BIT_PROTOCOL) && new->protocol != RTPROT_KEEPALIVED)
			report_config_error(CONFIG_GENERAL_ERROR, "Route cannot be tracked if protocol is not RTPROT_KEEPALIVED(%d), resetting protocol", RTPROT_KEEPALIVED);
		new->protocol = RTPROT_KEEPALIVED;
		new->mask |= IPROUTE_BIT_PROTOCOL;

		if (!new->oif) {
			/* Alternative is to track oif from when route last added.
			 * The interface will need to be added temporarily. tracking_vrrp_t will need
			 * a flag to specify permanent track, and a counter for number of temporary
			 * trackers. If the termporary tracker count becomes 0 and there is no permanent
			 * track, then the tracking_vrrp_t will need to be removed.
			 *
			 * We also have a problem if using nexthop, since the route will only be deleted
			 * when the interfaces for all of the hops have gone down. We would need to track
			 * all of the interfaces being used, and only mark the route as down if all the
			 * interfaces are down. */
			//report_config_error(CONFIG_GENERAL_ERROR, "Warning - cannot track route %s with no interface specified, not tracking", dest);
			new->dont_track = true;
		}
	}

	if (new->track_group && !new->oif) {
		//report_config_error(CONFIG_GENERAL_ERROR, "Static route cannot have track group if no oif specified");
		new->track_group = NULL;
	}

	/* Check that family is set */
	if (new->family == AF_UNSPEC)
		new->family = AF_INET;
	if (new->dst->ifa.ifa_family == AF_UNSPEC)
		new->dst->ifa.ifa_family = new->family;
	if (new->src && new->src->ifa.ifa_family == AF_UNSPEC)
		new->src->ifa.ifa_family = new->family;

	list_add(rt_list, new);

	return;

err:
	free_iproute(new);
}

/* Try to find a route in a list */
static ip_route_t *
route_exist(list l, ip_route_t *iproute)
{
	ip_route_t *ipr;
	element e;

	LIST_FOREACH(l, ipr, e) {
		/* The kernel's key to a route is (to, tos, preference, table) */
		if (IP_ISEQ(ipr->dst, iproute->dst) &&
		    ipr->dst->ifa.ifa_prefixlen == iproute->dst->ifa.ifa_prefixlen &&
		    (!((ipr->mask ^ iproute->mask) & IPROUTE_BIT_METRIC)) &&
		    (!(ipr->mask & IPROUTE_BIT_METRIC) ||
		     ipr->metric == iproute->metric) &&
		    ipr->table == iproute->table) {
			ipr->set = iproute->set;
			return ipr;
		}
	}
	return NULL;
}

/* Clear diff routes */
void
clear_diff_routes(list l, list n)
{
	ip_route_t *iproute, *new_iproute;
	element e;

	/* No route in previous conf */
	if (LIST_ISEMPTY(l))
		return;

	/* All routes removed */
	if (LIST_ISEMPTY(n)) {
		log_message(LOG_INFO, "Removing a VirtualRoute block");
		netlink_rtlist(l, IPROUTE_DEL);
		return;
	}

	LIST_FOREACH(l, iproute, e) {
		if (iproute->set) {
			if (!(new_iproute = route_exist(n, iproute))) {
				log_message(LOG_INFO, "ip route %s/%d ... , no longer exist"
						    , ipaddresstos(NULL, iproute->dst), iproute->dst->ifa.ifa_prefixlen);
				netlink_route(iproute, IPROUTE_DEL);
			}
			else {
				/* There are too many route options to compare to see if the
				 * routes are the same or not, so just replace the existing route
				 * with the new one.
				 * We try replacing the route, but if, for example, it has a src
				 * address that is a new VIP, then the route won't be able to be
				 * added (replaced) now. In this case delete the old route, mark
				 * it as not set, and then it will be added later when any new
				 * routes are added. */
				netlink_error_ignore = EINVAL;
				if (netlink_route(new_iproute, IPROUTE_REPLACE)) {
					netlink_error_ignore = 0;
					netlink_route(iproute, IPROUTE_DEL);
					new_iproute->set = false;
				} else
					netlink_error_ignore = 0;
			}
		}
	}
}

/* Diff conf handler */
void
clear_diff_sroutes(void)
{
	clear_diff_routes(old_vrrp_data->static_routes, vrrp_data->static_routes);
}

void
reinstate_static_route(ip_route_t *route)
{
	char buf[256];

	route->set = !netlink_route(route, IPROUTE_ADD);

	format_iproute(route, buf, sizeof(buf));
	log_message(LOG_INFO, "Restoring deleted static route %s", buf);
}
