/*
 * libipvs:	Library for manipulating IPVS through netlink or [gs]etsockopt
 *
 *		This code is copied from the ipvsadm sources, with the unused
 *		code removed. It is available at:
 *		https://git.kernel.org/cgit/utils/kernel/ipvsadm/ipvsadm.git
 *
 *		The upstream code should periodically be checked for updates,
 *		which should then be applied to this code.
 *
 * Authors:	Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "libipvs.h"
#include "sockopt.h"
#include "dp_vs.h"

#include "memory.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif
#include "logger.h"
#include "ip_vs.h"

typedef int (*qsort_cmp_t)(const void *, const void *);

static int sockfd = -1;
static void* ipvs_func = NULL;

typedef struct dpvs_servicedest_s {
	struct dp_vs_service_user	svc;
	struct dp_vs_dest_user		dest; 
} dpvs_servicedest_t;

typedef struct dp_vs_service_entry_app {
    struct dp_vs_service_entry user;
} dpvs_service_entry_t;

// IPVS_2_DPVS(dp_vs_service_user, ip_vs_service_app/ipvs_service_t)
#define IPVS_2_DPVS(X, Y) {					\
	X->af               = Y->af; 				\
	X->proto 	    = Y->user.protocol; 		\
	memcpy(&X->addr, &Y->nf_addr, sizeof(X->addr)); 	\
	X->port             = Y->user.port; 			\
	X->fwmark           = Y->user.fwmark; 			\
	X->flags            = Y->user.flags; 			\
	X->timeout          = Y->user.timeout; 			\
	X->conn_timeout     = Y->user.conn_timeout; 		\
	X->netmask          = Y->user.netmask; 			\
	X->bps              = Y->user.bps; 			\
	X->limit_proportion = Y->user.limit_proportion; 	\
	snprintf(X->sched_name, IP_VS_SCHEDNAME_MAXLEN, "%s", Y->user.sched_name); \
	snprintf(X->srange, sizeof(X->srange), "%s", Y->user.srange); \
	snprintf(X->drange, sizeof(X->drange), "%s", Y->user.drange); \
	snprintf(X->iifname, sizeof(X->iifname), "%s", Y->user.iifname); \
	snprintf(X->oifname, sizeof(X->oifname), "%s", Y->user.oifname);}

// DPVS_2_IPVS(ipvs_service_entry_t, dpvs_service_entry_t)
#define DPVS_2_IPVS(X, Y) {					\
	X->af               	= Y->user.af; 				\
	memcpy(&X->nf_addr, &Y->user.addr, sizeof(X->nf_addr)); 	\
	X->user.protocol 	= Y->user.proto; 			\
	X->user.port            = Y->user.port; 			\
	X->user.fwmark          = Y->user.fwmark; 			\
	snprintf(X->user.sched_name, IP_VS_SCHEDNAME_MAXLEN, "%s", Y->user.sched_name); \
	X->user.flags           = Y->user.flags; 			\
	X->user.timeout         = Y->user.timeout; 			\
	X->user.conn_timeout    = Y->user.conn_timeout; 			\
	X->user.netmask         = Y->user.netmask; 			\
	X->user.bps             = Y->user.bps; 				\
	X->user.limit_proportion= Y->user.limit_proportion; 		\
	X->user.num_dests        = Y->user.num_dests;			\
	X->user.num_laddrs       = Y->user.num_laddrs;			\
	snprintf(X->user.srange, sizeof(X->user.srange), "%s", Y->user.srange); \
	snprintf(X->user.drange, sizeof(X->user.drange), "%s", Y->user.drange); \
	snprintf(X->user.iifname, sizeof(X->user.iifname), "%s", Y->user.iifname); \
	snprintf(X->user.oifname, sizeof(X->user.oifname), "%s", Y->user.oifname); \
	memcpy(&X->user.stats, &Y->user.stats, sizeof(X->user.stats));}

#define IPRS_2_DPRS(X, Y) {					\
	X->af               = Y->af; 				\
	memcpy(&X->addr, &Y->nf_addr, sizeof(X->addr)); 	\
	X->port             = Y->user.port; 			\
	X->conn_flags       = Y->user.conn_flags; 		\
	X->weight           = Y->user.weight; 			\
	X->max_conn         = Y->user.u_threshold; 		\
	X->min_conn         = Y->user.l_threshold;}

// DPRS_2_IPRS(ip_vs_dest_entry_app, dp_vs_dest_entry)
#define DPRS_2_IPRS(X, Y) {					\
	X->af               = Y->af; 				\
	memcpy(&X->nf_addr, &Y->addr, sizeof(X->nf_addr)); 		\
	X->user.port             = Y->port; 				\
	X->user.conn_flags       = Y->conn_flags; 			\
	X->user.weight           = Y->weight; 			\
	X->user.u_threshold      = Y->max_conn; 			\
	X->user.l_threshold      = Y->min_conn;			\
	X->user.activeconns      = Y->actconns;			\
	X->user.inactconns       = Y->inactconns;			\
	X->user.persistconns     = Y->persistconns;			\
	memcpy(&X->stats, &Y->stats, sizeof(X->stats));}

static void ipvs_service_entry_2_user(const ipvs_service_entry_t *entry, ipvs_service_t *rule)
{
	rule->user.protocol  = entry->user.protocol;
	rule->user.__addr_v4 = entry->user.__addr_v4;
	rule->user.port      = entry->user.port;
	rule->user.fwmark    = entry->user.fwmark;
	strcpy(rule->user.sched_name, entry->user.sched_name);
	rule->user.flags     = entry->user.flags;
	rule->user.timeout   = entry->user.timeout;
	rule->user.conn_timeout = entry->user.conn_timeout;
	rule->user.netmask   = entry->user.netmask;
	rule->af        = entry->af;
	rule->nf_addr      = entry->nf_addr;
	strcpy(rule->pe_name, entry->pe_name);
	strcpy(rule->user.srange, entry->user.srange);
	strcpy(rule->user.drange, entry->user.drange);
	strcpy(rule->user.iifname, entry->user.iifname);
	strcpy(rule->user.iifname, entry->user.iifname);
}

struct ip_vs_getinfo g_ipvs_info;

int ipvs_init(lcoreid_t cid)
{
	//socklen_t len, len_rcv;
	size_t len, len_rcv;
	struct ip_vs_getinfo *ipvs_info_rcv;

	ipvs_func = ipvs_init;

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(sockfd, F_SETFD, FD_CLOEXEC)) {
		close(sockfd);
		return -1;
	}
#endif
	len = sizeof(g_ipvs_info);
	len_rcv = len;

	if (dpvs_getsockopt(DPVS_SO_GET_INFO, (const void*)&g_ipvs_info, len, (void **)&ipvs_info_rcv, &len_rcv)) {
		return -1;
	}

	memcpy(&g_ipvs_info, ipvs_info_rcv, sizeof(g_ipvs_info));

	dpvs_sockopt_msg_free(ipvs_info_rcv);

	return 0;
}

int ipvs_flush(void)
{
	return dpvs_setsockopt(DPVS_SO_SET_FLUSH, NULL, 0);
}

int ipvs_add_service(ipvs_service_t *svc)
{
	struct dp_vs_service_user dpvs_svc;

	ipvs_func = ipvs_add_service;

	IPVS_2_DPVS((&dpvs_svc), svc);

	return dpvs_setsockopt(DPVS_SO_SET_ADD, &dpvs_svc, sizeof(dpvs_svc));
}

int ipvs_update_service(ipvs_service_t *svc)
{
	struct dp_vs_service_user dpvs_svc;

	ipvs_func = ipvs_update_service;

	IPVS_2_DPVS((&dpvs_svc), svc);

	return dpvs_setsockopt(DPVS_SO_SET_EDIT, &dpvs_svc, sizeof(dpvs_svc));
}

int ipvs_update_service_by_options(ipvs_service_t *svc, unsigned int options)
{
	ipvs_service_entry_t *entry;
	ipvs_service_t app;

	if (!(entry = ipvs_get_service(svc, 0))) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		return ESOCKOPT_INVAL;
	}
	ipvs_service_entry_2_user(entry, &app);

	if (options & OPT_SCHEDULER) {
		strcpy(app.user.sched_name, svc->user.sched_name);
		if (strcmp(svc->user.sched_name, "conhash")) {
			app.user.flags &= ~IP_VS_SVC_F_QID_HASH;
			app.user.flags &= ~IP_VS_SVC_F_SIP_HASH;
		} else {
			app.user.flags |= IP_VS_SVC_F_SIP_HASH;
		}
	}

	if (options & OPT_PERSISTENT) {
		app.user.flags  |= IP_VS_SVC_F_PERSISTENT;
		app.user.timeout = svc->user.timeout;
	}

	if (options & OPT_NETMASK) {
		app.user.netmask = svc->user.netmask;
	}

	if (options & OPT_SYNPROXY) {
		if(svc->user.flags & IP_VS_CONN_F_SYNPROXY) {
			app.user.flags |= IP_VS_CONN_F_SYNPROXY;
		} else {
			app.user.flags &= ~IP_VS_CONN_F_SYNPROXY;
		}
	}

	if (options & OPT_EXPIRE_QUIESCENT_CONN) {
		if (svc->user.flags & IP_VS_CONN_F_EXPIRE_QUIESCENT) {
			app.user.flags |= IP_VS_CONN_F_EXPIRE_QUIESCENT;
		} else {
			app.user.flags &= ~IP_VS_CONN_F_EXPIRE_QUIESCENT;
		}
	}

	if (options & OPT_ONEPACKET) {
		app.user.flags |= IP_VS_SVC_F_ONEPACKET;
	}

	if (options & OPT_HASHTAG) {
		app.user.flags &= ~ IP_VS_SVC_F_QID_HASH;
		app.user.flags &= ~ IP_VS_SVC_F_SIP_HASH;
		if (svc->user.flags & IP_VS_SVC_F_SIP_HASH) {
			app.user.flags |= IP_VS_SVC_F_SIP_HASH;
		} else if (svc->user.flags & IP_VS_SVC_F_QID_HASH) {
			app.user.flags |= IP_VS_SVC_F_QID_HASH;
		} else {
			app.user.flags |= IP_VS_SVC_F_SIP_HASH;
		}
	}

	return ipvs_update_service(&app);
}

int ipvs_update_service_synproxy(ipvs_service_t *svc , int enable)
{
	unsigned int options = OPT_NONE;

	options |= OPT_SYNPROXY;

	if (enable)
		svc->user.flags |= IP_VS_CONN_F_SYNPROXY;
	else
		svc->user.flags &= (~IP_VS_CONN_F_SYNPROXY);
	
	return ipvs_update_service_by_options(svc, options);
}

int ipvs_del_service(ipvs_service_t *svc)
{
	struct dp_vs_service_user dpvs_svc;

	ipvs_func = ipvs_del_service;

	IPVS_2_DPVS((&dpvs_svc), svc);

	return dpvs_setsockopt(DPVS_SO_SET_DEL, &dpvs_svc, sizeof(dpvs_svc));
}

int ipvs_zero_service(ipvs_service_t *svc)
{
	struct dp_vs_service_user dpvs_svc;

	ipvs_func = ipvs_zero_service;

	IPVS_2_DPVS((&dpvs_svc), svc);

	return dpvs_setsockopt(DPVS_SO_SET_ZERO, &dpvs_svc, sizeof(dpvs_svc));
}

int ipvs_add_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	dpvs_servicedest_t svcdest;
	struct dp_vs_service_user *dpvs_svc_ptr = &svcdest.svc;
	struct dp_vs_dest_user *dpvs_dest_ptr = &svcdest.dest;

	ipvs_func = ipvs_add_dest;

	IPVS_2_DPVS(dpvs_svc_ptr, svc);
	IPRS_2_DPRS(dpvs_dest_ptr, dest);

	return dpvs_setsockopt(DPVS_SO_SET_ADDDEST, &svcdest, sizeof(svcdest));
}

int ipvs_update_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	dpvs_servicedest_t svcdest;
	struct dp_vs_service_user *dpvs_svc_ptr = &svcdest.svc;
	struct dp_vs_dest_user *dpvs_dest_ptr = &svcdest.dest;

	ipvs_func = ipvs_update_dest;

	IPVS_2_DPVS(dpvs_svc_ptr, svc);
	IPRS_2_DPRS(dpvs_dest_ptr, dest);

	return dpvs_setsockopt(DPVS_SO_SET_EDITDEST, &svcdest, sizeof(svcdest));
}

int ipvs_del_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	dpvs_servicedest_t svcdest;
	struct dp_vs_service_user *dpvs_svc_ptr = &svcdest.svc;
	struct dp_vs_dest_user *dpvs_dest_ptr = &svcdest.dest;

	ipvs_func = ipvs_del_dest;

	IPVS_2_DPVS(dpvs_svc_ptr, svc);
	IPRS_2_DPRS(dpvs_dest_ptr, dest);

	return dpvs_setsockopt(DPVS_SO_SET_DELDEST, &svcdest, sizeof(svcdest));
}

static void ipvs_fill_laddr_conf(ipvs_service_t *svc, ipvs_laddr_t *laddr, 
                                 struct dp_vs_laddr_conf *conf)
{
	memset(conf, 0, sizeof(*conf));

	conf->af_s      = svc->af;
	conf->af_l      = laddr->af;
	conf->proto     = svc->user.protocol;
	conf->vport     = svc->user.port;
	conf->fwmark    = svc->user.fwmark;

	if (strlen(laddr->ifname))
		snprintf(conf->ifname, sizeof(conf->ifname), "%s", laddr->ifname);

	if (svc->af == AF_INET) {
		conf->vaddr.in = svc->nf_addr.in;
		conf->laddr.in = laddr->addr.in;
	} else {
		conf->vaddr.in6 = svc->nf_addr.in6;
		conf->laddr.in6 = laddr->addr.in6;
	}    

	return ;
}

static void ipvs_fill_ipaddr_conf(int is_add, uint32_t flags,
                                  ipvs_laddr_t *laddr, struct inet_addr_param *param)
{
	memset(param, 0, sizeof(*param));

	if (is_add)
		param->ifa_ops = INET_ADDR_ADD;
	else
		param->ifa_ops = INET_ADDR_DEL;
	param->ifa_ops_flags = flags;
	param->ifa_entry.af = laddr->af;
	if (strlen(laddr->ifname))
		snprintf(param->ifa_entry.ifname, sizeof(param->ifa_entry.ifname), "%s", laddr->ifname);
	if (laddr->af == AF_INET) {
		param->ifa_entry.addr.in = laddr->addr.in;
		param->ifa_entry.plen = 32;
	} else {
		param->ifa_entry.plen = 128;
		param->ifa_entry.addr.in6 = laddr->addr.in6;
	}
	param->ifa_entry.flags |= IFA_F_SAPOOL;

	return;
}

int ipvs_add_laddr(ipvs_service_t *svc, ipvs_laddr_t *laddr)
{
	struct dp_vs_laddr_conf conf;
	struct inet_addr_param param;

	ipvs_func = ipvs_add_laddr;

	ipvs_fill_laddr_conf(svc, laddr, &conf);
	ipvs_fill_ipaddr_conf(1, 0, laddr, &param);
	ipvs_set_ipaddr(&param, 1);

	return dpvs_setsockopt(SOCKOPT_SET_LADDR_ADD, &conf, sizeof(conf));
}

int ipvs_del_laddr(ipvs_service_t *svc, ipvs_laddr_t *laddr)
{
	struct dp_vs_laddr_conf conf;
	struct inet_addr_param param;

	ipvs_func = ipvs_del_laddr;

	ipvs_fill_laddr_conf(svc, laddr, &conf);
	ipvs_fill_ipaddr_conf(0, 0, laddr, &param);
	ipvs_set_ipaddr(&param, 0);

	return dpvs_setsockopt(SOCKOPT_SET_LADDR_DEL, &conf, sizeof(conf));
}

/*for black list*/
static void ipvs_fill_blklst_conf(ipvs_service_t *svc, ipvs_blklst_t *blklst,
                                 struct dp_vs_blklst_conf *conf)
{
	memset(conf, 0, sizeof(*conf));
	conf->af        = svc->af;
	conf->proto     = svc->user.protocol;
	conf->vport     = svc->user.port;
	conf->fwmark    = svc->user.fwmark;
	if (svc->af == AF_INET) {
		conf->vaddr.in = svc->nf_addr.in;
		conf->blklst.in = blklst->addr.in;
	} else {
		conf->vaddr.in6 = svc->nf_addr.in6;
		conf->blklst.in6 = blklst->addr.in6;
	}

	return;
}
int ipvs_add_blklst(ipvs_service_t *svc, ipvs_blklst_t *blklst)
{
	struct dp_vs_blklst_conf conf;

	ipvs_func = ipvs_add_blklst;

	ipvs_fill_blklst_conf(svc, blklst, &conf);

	return dpvs_setsockopt(SOCKOPT_SET_BLKLST_ADD, &conf, sizeof(conf));
}

int ipvs_del_blklst(ipvs_service_t *svc, ipvs_blklst_t *blklst)
{
	struct dp_vs_blklst_conf conf;

	ipvs_func = ipvs_del_blklst;

	ipvs_fill_blklst_conf(svc, blklst, &conf);

	return dpvs_setsockopt(SOCKOPT_SET_BLKLST_DEL, &conf, sizeof(conf));
}

/*for white list*/
static void ipvs_fill_whtlst_conf(ipvs_service_t *svc, ipvs_whtlst_t *whtlst,
                                 struct dp_vs_whtlst_conf *conf)
{
	memset(conf, 0, sizeof(*conf));
	conf->af        = svc->af;
	conf->proto     = svc->user.protocol;
	conf->vport     = svc->user.port;
	conf->fwmark    = svc->user.fwmark;
	if (svc->af == AF_INET) {
		conf->vaddr.in = svc->nf_addr.in;
		conf->whtlst.in = whtlst->addr.in;
	} else {
		conf->vaddr.in6 = svc->nf_addr.in6;
		conf->whtlst.in6 = whtlst->addr.in6;
	}

	return;
}

int ipvs_add_whtlst(ipvs_service_t *svc, ipvs_whtlst_t *whtlst)
{
	struct dp_vs_whtlst_conf conf;

	ipvs_func = ipvs_add_whtlst;

	ipvs_fill_whtlst_conf(svc, whtlst, &conf);

	return dpvs_setsockopt(SOCKOPT_SET_WHTLST_ADD, &conf, sizeof(conf));
}

int ipvs_del_whtlst(ipvs_service_t *svc, ipvs_whtlst_t *whtlst)
{
	struct dp_vs_whtlst_conf conf;

	ipvs_func = ipvs_del_whtlst;

	ipvs_fill_whtlst_conf(svc, whtlst, &conf);

	return dpvs_setsockopt(SOCKOPT_SET_WHTLST_DEL, &conf, sizeof(conf));
}

/* for tunnel entry */
static void ipvs_fill_tunnel_conf(ipvs_tunnel_t *tunnel_entry,
                                 struct ip_tunnel_param *conf)
{
	memset(conf, 0, sizeof(*conf));

	strncpy(conf->ifname, tunnel_entry->ifname, sizeof(conf->ifname));
	strncpy(conf->kind, tunnel_entry->kind, sizeof(conf->kind));
	strncpy(conf->link, tunnel_entry->link, sizeof(conf->link));
	conf->iph.saddr = tunnel_entry->laddr.ip;
	conf->iph.daddr = tunnel_entry->raddr.ip;
	return;
}

int ipvs_add_tunnel(ipvs_tunnel_t *tunnel_entry)
{
	struct ip_tunnel_param conf;

	ipvs_func = ipvs_add_tunnel;

	ipvs_fill_tunnel_conf(tunnel_entry, &conf);

	return dpvs_setsockopt(SOCKOPT_TUNNEL_ADD, &conf, sizeof(conf));
}

int ipvs_del_tunnel(ipvs_tunnel_t *tunnel_entry)
{
	struct ip_tunnel_param conf;

	ipvs_func = ipvs_del_tunnel;

	ipvs_fill_tunnel_conf(tunnel_entry, &conf);

	return dpvs_setsockopt(SOCKOPT_TUNNEL_DEL, &conf, sizeof(conf));
}

int ipvs_set_timeout(ipvs_timeout_t *to)
{
	ipvs_func = ipvs_set_timeout;

	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_TIMEOUT, (char *)to,
			  sizeof(*to));
}

int ipvs_start_daemon(ipvs_daemon_t *dm)
{
	ipvs_func = ipvs_start_daemon;

	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STARTDAEMON,
			  (char *)&dm, sizeof(dm));
}


int ipvs_stop_daemon(ipvs_daemon_t *dm)
{
	ipvs_func = ipvs_stop_daemon;

	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STOPDAEMON,
			  (char *)&dm, sizeof(dm));
}

static inline sockoptid_t cpu2opt_svc(lcoreid_t cid, sockoptid_t old_opt)
{
	return old_opt + cid * (SOCKOPT_SVC_GET_CMD_MAX - SOCKOPT_SVC_BASE + 1);
}

/* now support get_all only */
static inline sockoptid_t cpu2opt_laddr(lcoreid_t cid, sockoptid_t old_opt)
{
	return old_opt + cid;
}

struct ip_vs_get_services_app *ipvs_get_services(lcoreid_t cid)
{
	struct ip_vs_get_services_app *get;
	struct ip_vs_service_entry_app *ipvs_entry;
	struct dp_vs_get_services *dpvs_get, *dpvs_get_rcv;
	dpvs_service_entry_t *dpvs_entry;
	size_t len = 0, len_rcv = 0;
	unsigned int i;

	ipvs_func = ipvs_get_services;

	len = sizeof(struct ip_vs_get_services_app) +
		sizeof(ipvs_service_entry_t) * g_ipvs_info.num_services;
	if (!(get = calloc(len, 1)))
		return NULL;

	len = sizeof(struct dp_vs_get_services);
	if (!(dpvs_get = calloc(len, 1))) {
		free(get);
		return NULL;
	}
	dpvs_get->num_services = g_ipvs_info.num_services;
	dpvs_get->cid = cid;
	if (dpvs_getsockopt(cpu2opt_svc(cid, DPVS_SO_GET_SERVICES), dpvs_get, len,
				(void **)&dpvs_get_rcv, &len_rcv)) {
		free(get);
		free(dpvs_get);
		return NULL;
	}

	get->user.num_services = dpvs_get_rcv->num_services;
	g_ipvs_info.num_services = dpvs_get_rcv->num_services;
	for (i = 0; i < dpvs_get_rcv->num_services; i++) {
		ipvs_entry = &get->user.entrytable[i];
		dpvs_entry = (dpvs_service_entry_t*)&dpvs_get_rcv->entrytable[i];
		DPVS_2_IPVS(ipvs_entry, dpvs_entry);
		if (dpvs_get_rcv->entrytable[i].af == AF_INET) {
			get->user.entrytable[i].user.__addr_v4 = get->user.entrytable[i].nf_addr.ip;
			get->user.entrytable[i].pe_name[0] = '\0';
		}
	}

	free(dpvs_get);
	dpvs_sockopt_msg_free(dpvs_get_rcv);
	return get;
}

#ifdef _WITH_SNMP_CHECKER_
#endif	/* _WITH_SNMP_CHECKER_ */

struct ip_vs_get_dests_app *ipvs_get_dests(ipvs_service_entry_t *svc, lcoreid_t cid)
{
	struct ip_vs_get_dests_app *d;
	struct dp_vs_get_dests *dpvs_dests, *dpvs_dests_rcv;
	struct ip_vs_dest_entry_app *ipvs_entry;
	struct dp_vs_dest_entry *dpvs_entry;
	size_t len = 0, len_rcv = 0;
	unsigned i;

	ipvs_func = ipvs_get_dests;

	len = sizeof(struct ip_vs_get_dests_app) + 
		sizeof(ipvs_dest_entry_t) * svc->user.num_dests;
	if (!(d = calloc(len, 1)))
		return NULL;

	len = sizeof(struct dp_vs_get_dests);
	if (!(dpvs_dests = calloc(len, 1))) {
		free(d);
		return NULL;
	}

	dpvs_dests->af = svc->af;
	dpvs_dests->fwmark = svc->user.fwmark;
	dpvs_dests->proto = svc->user.protocol;
	memcpy(&dpvs_dests->addr, &svc->nf_addr, sizeof(svc->nf_addr));
	dpvs_dests->port = svc->user.port;
	dpvs_dests->num_dests = svc->user.num_dests;
	dpvs_dests->cid = cid;
	snprintf(dpvs_dests->srange, sizeof(dpvs_dests->srange), "%s", svc->user.srange);
	snprintf(dpvs_dests->drange, sizeof(dpvs_dests->drange), "%s", svc->user.drange);
	snprintf(dpvs_dests->iifname, sizeof(dpvs_dests->iifname), "%s", svc->user.iifname);
	snprintf(dpvs_dests->oifname, sizeof(dpvs_dests->oifname), "%s", svc->user.oifname);

	if (dpvs_getsockopt(cpu2opt_svc(cid, DPVS_SO_GET_DESTS), dpvs_dests, len,
				(void **)&dpvs_dests_rcv, &len_rcv) < 0) {
		free(d);
		free(dpvs_dests);
		return NULL;
	}

	d->af = dpvs_dests_rcv->af;
	memcpy(&d->nf_addr, &dpvs_dests_rcv->addr, sizeof(d->nf_addr));
	d->user.protocol  = dpvs_dests_rcv->proto;
	d->user.port = dpvs_dests_rcv->port;
	d->user.fwmark = dpvs_dests_rcv->fwmark;
	d->user.num_dests = dpvs_dests_rcv->num_dests;
	snprintf(d->user.srange, sizeof(dpvs_dests_rcv->srange), "%s", dpvs_dests_rcv->srange);
	snprintf(d->user.drange, sizeof(dpvs_dests_rcv->drange), "%s", dpvs_dests_rcv->drange);
	snprintf(d->user.iifname, sizeof(dpvs_dests_rcv->iifname), "%s", dpvs_dests_rcv->iifname);
	snprintf(d->user.oifname, sizeof(dpvs_dests_rcv->oifname), "%s", dpvs_dests_rcv->oifname);
	if (d->af == AF_INET) {
		d->user.__addr_v4 = d->nf_addr.ip;
	}
	for (i = 0; i < dpvs_dests_rcv->num_dests; i++) {
		ipvs_entry = &d->user.entrytable[i];
		dpvs_entry = &dpvs_dests_rcv->entrytable[i];
		DPRS_2_IPRS(ipvs_entry, dpvs_entry);
		if (d->user.entrytable[i].af == AF_INET)
			d->user.entrytable[i].user.__addr_v4 = d->user.entrytable[i].nf_addr.ip;
	}
	free(dpvs_dests);	
	dpvs_sockopt_msg_free(dpvs_dests_rcv);
	return d;
}

ipvs_service_entry_t *
ipvs_get_service(ipvs_service_t *hint, lcoreid_t cid)
{
	ipvs_service_entry_t *svc;
	size_t len, len_rcv;
	dpvs_service_entry_t dpvs_svc, *dpvs_svc_rcv;
	struct dp_vs_service_user dpvs_app, *dpvs_app_ptr;

	ipvs_func = ipvs_get_service;

	len = sizeof(*svc);
	svc = calloc(1, len);
	if (!svc)
		return NULL;
	memset((void*)svc, 0x00, len);

	len = sizeof(dpvs_svc);
	len_rcv = sizeof(*dpvs_svc_rcv);
	memset(&dpvs_svc, 0, len);

	dpvs_app_ptr = &dpvs_app;
	memset(dpvs_app_ptr, 0, sizeof(dpvs_app));
	IPVS_2_DPVS(dpvs_app_ptr, hint);
	memcpy(&dpvs_svc, dpvs_app_ptr, sizeof(dpvs_app));
	dpvs_svc.user.cid = cid;

	if (dpvs_getsockopt(cpu2opt_svc(cid, DPVS_SO_GET_SERVICE), 
		&dpvs_svc, 
		len, 
		(void **)&dpvs_svc_rcv, 
		&len_rcv)) {
		goto out_err;
	}
	
	DPVS_2_IPVS(svc, dpvs_svc_rcv)
	if (svc->af == AF_INET) {
		svc->pe_name[0] = '\0';
		svc->user.__addr_v4 = svc->nf_addr.ip;
	}

	dpvs_sockopt_msg_free(dpvs_svc_rcv);
	return svc;
out_err:
	FREE(svc);
	return NULL;
}

int __attribute__ ((pure))
ipvs_cmp_services(ipvs_service_entry_t *s1, ipvs_service_entry_t *s2)
{
	int r, i;

	r = s1->user.fwmark - s2->user.fwmark;
	if (r != 0)
		return r;

	r = s1->af - s2->af;
	if (r != 0)
		return r;

	r = s1->user.protocol - s2->user.protocol;
	if (r != 0)
		return r;

	if (s1->af == AF_INET6)
		for (i = 0; !r && (i < 4); i++)
			r = ntohl(s1->nf_addr.in6.s6_addr32[i]) - ntohl(s2->nf_addr.in6.s6_addr32[i]);
	else
		r = ntohl(s1->nf_addr.ip) - ntohl(s2->nf_addr.ip);
	if (r != 0)
		return r;

	return ntohs(s1->user.port) - ntohs(s2->user.port);
}

int __attribute__ ((pure))
ipvs_cmp_dests(ipvs_dest_entry_t *d1, ipvs_dest_entry_t *d2)
{
	int r = 0, i;

	if (d1->af == AF_INET6)
		for (i = 0; !r && (i < 4); i++)
			r = ntohl(d1->nf_addr.in6.s6_addr32[i]) -
			    ntohl(d2->nf_addr.in6.s6_addr32[i]);
	else
		r = ntohl(d1->nf_addr.ip) - ntohl(d2->nf_addr.ip);
	if (r != 0)
		return r;

	return ntohs(d1->user.port) - ntohs(d2->user.port);
}

void
ipvs_sort_services(struct ip_vs_get_services_app *s, ipvs_service_cmp_t f)
{
	qsort(s->user.entrytable, s->user.num_services,
	      sizeof(ipvs_service_entry_t), (qsort_cmp_t)f);
}

void ipvs_sort_dests(struct ip_vs_get_dests_app *d, ipvs_dest_cmp_t f)
{
	qsort(d->user.entrytable, d->user.num_dests,
	      sizeof(ipvs_dest_entry_t), (qsort_cmp_t)f);
}

int ipvs_set_route(struct dp_vs_route_conf *rt, int cmd)
{
	int err = -1;

	ipvs_func = ipvs_set_route;

	if (cmd == IPROUTE_DEL){
		err = dpvs_setsockopt(SOCKOPT_SET_ROUTE_DEL, rt, sizeof(struct dp_vs_route_conf));
	} else if (cmd == IPROUTE_ADD){
		err = dpvs_setsockopt(SOCKOPT_SET_ROUTE_ADD, rt, sizeof(struct dp_vs_route_conf));
	}

	return err;
}

int ipvs_set_route6(struct dp_vs_route6_conf *rt6_cfg, int cmd)
{
	int err = -1;

	ipvs_func = ipvs_set_route6;

	if (cmd == IPROUTE_DEL) {
		rt6_cfg->ops = RT6_OPS_DEL;
		err = dpvs_setsockopt(SOCKOPT_SET_ROUTE6_ADD_DEL, rt6_cfg,
						sizeof(struct dp_vs_route6_conf));
	} else if (cmd == IPROUTE_ADD) {
		rt6_cfg->ops = RT6_OPS_ADD;
		err = dpvs_setsockopt(SOCKOPT_SET_ROUTE6_ADD_DEL, rt6_cfg,
						sizeof(struct dp_vs_route6_conf));
	}
	return err;
}

int ipvs_set_ipaddr(struct inet_addr_param *param, int cmd)
{
	int err = -1;

	ipvs_func = ipvs_set_ipaddr;

	if (cmd == IPADDRESS_DEL)
	   err = dpvs_setsockopt(SOCKOPT_SET_IFADDR_DEL, param, sizeof(struct inet_addr_param));
	else if (cmd == IPADDRESS_ADD)
	   err = dpvs_setsockopt(SOCKOPT_SET_IFADDR_ADD, param, sizeof(struct inet_addr_param));

	return err;
}

int ipvs_send_gratuitous_arp(struct in_addr *in)
{
	ipvs_func = ipvs_send_gratuitous_arp;

	return dpvs_setsockopt(DPVS_SO_SET_GRATARP, in, sizeof(in));
}

ipvs_timeout_t *ipvs_get_timeout(void)
{
#if 0
	ipvs_timeout_t *u;
	socklen_t len;

	ipvs_func = ipvs_get_timeout;

	len = sizeof(*u);
	if (!(u = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_timeout;
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_TIMEOUT,
		       (char *)u, &len)) {
		free(u);
		return NULL;
	}
#endif
	return NULL;
}

ipvs_daemon_t *ipvs_get_daemon(void)
{
#if 0
	ipvs_daemon_t *u;
	socklen_t len;

	/* note that we need to get the info about two possible
	   daemons, master and backup. */
	len = sizeof(*u) * 2;
	if (!(u = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_daemon;
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_DAEMON, (char *)u, &len)) {
		free(u);
		return NULL;
	}
#endif

	return NULL;
}

void ipvs_close(void)
{
	if (sockfd != -1) {
		close(sockfd);
		sockfd = -1;
	}
}

struct ip_vs_conn_array *ip_vs_get_conns(const struct ip_vs_conn_req *req)
{
	int res;
	size_t arrlen, rcvlen;
	struct ip_vs_conn_array *conn_arr, *arr_rcv;

	ipvs_func = ip_vs_get_conns;

	if (req->flag & GET_IPVS_CONN_FLAG_SPECIFIED)
		res = dpvs_getsockopt(SOCKOPT_GET_CONN_SPECIFIED, req,
				sizeof(struct ip_vs_conn_req),
				(void **)&arr_rcv, &rcvlen);
	else
		res = dpvs_getsockopt(SOCKOPT_GET_CONN_ALL, req,
				sizeof(struct ip_vs_conn_req),
				(void **)&arr_rcv, &rcvlen);

	if (res != ESOCKOPT_OK) {
		fprintf(stderr, "%s: got errcode %d from dpvs_getsockopt\n", __func__, res);
		return NULL;
	}

	if (req->flag & GET_IPVS_CONN_FLAG_SPECIFIED)
		arrlen = sizeof(struct ip_vs_conn_array) + sizeof(ipvs_conn_entry_t);
	else
		arrlen = sizeof(struct ip_vs_conn_array) + MAX_CTRL_CONN_GET_ENTRIES *
			sizeof(ipvs_conn_entry_t);

	if (!arr_rcv || rcvlen > arrlen) {
		fprintf(stderr, "%s: bad sockopt connection repsonse\n", __func__);
		return NULL;
	}

	conn_arr = calloc(1, arrlen);
	if (!conn_arr) {
		dpvs_sockopt_msg_free(arr_rcv);
		fprintf(stderr, "%s: out of memory\n", __func__);
		return NULL;
	}

	memcpy(conn_arr, arr_rcv, rcvlen);
	dpvs_sockopt_msg_free(arr_rcv);

	return conn_arr;
}

struct ip_vs_get_laddrs *ipvs_get_laddrs(ipvs_service_entry_t *svc, lcoreid_t cid)
{
	struct ip_vs_get_laddrs *laddrs;
	struct dp_vs_laddr_conf conf, *result;
	size_t res_size;
	int i;

	ipvs_func = ipvs_get_laddrs;

	memset(&conf, 0, sizeof(struct dp_vs_laddr_conf));
	conf.af_s = svc->af;
	conf.proto = svc->user.protocol;
	if (svc->af == AF_INET)
		conf.vaddr.in = svc->nf_addr.in;
	else
		conf.vaddr.in6 = svc->nf_addr.in6;
	conf.vport = svc->user.port;
	conf.fwmark = svc->user.fwmark;
	conf.cid = cid;

	snprintf(conf.srange, sizeof(conf.srange), "%s", svc->user.srange);
	snprintf(conf.drange, sizeof(conf.drange), "%s", svc->user.drange);
	snprintf(conf.iifname, sizeof(conf.iifname), "%s", svc->user.iifname);
	snprintf(conf.iifname, sizeof(conf.oifname), "%s", svc->user.oifname);

	if (dpvs_getsockopt(cpu2opt_laddr(cid, SOCKOPT_GET_LADDR_GETALL), &conf, sizeof(conf),
				(void **)&result, &res_size) != 0)
		return NULL;

	laddrs = malloc(sizeof(*laddrs) + result->nladdrs * sizeof(struct ip_vs_laddr_entry));
	if (!laddrs) {
		dpvs_sockopt_msg_free(result);
		return NULL;
	}

	laddrs->protocol = result->proto;
	laddrs->__addr_v4 = result->vaddr.in.s_addr;
	laddrs->port = result->vport;
	laddrs->fwmark = result->fwmark;
	laddrs->num_laddrs = result->nladdrs;
	laddrs->af = result->af_s;
	if (result->af_s == AF_INET)
		laddrs->addr.in = result->vaddr.in;
	else
		laddrs->addr.in6 = result->vaddr.in6;

	for (i = 0; i < result->nladdrs; i++) {
		laddrs->entrytable[i].__addr_v4 = result->laddrs[i].addr.in.s_addr;
		laddrs->entrytable[i].port_conflict = result->laddrs[i].nport_conflict;
		laddrs->entrytable[i].conn_counts = result->laddrs[i].nconns;
		laddrs->entrytable[i].af = result->laddrs[i].af;
		if (result->laddrs[i].af == AF_INET)
			laddrs->entrytable[i].addr.in = result->laddrs[i].addr.in;
		else
			laddrs->entrytable[i].addr.in6 = result->laddrs[i].addr.in6;
	}

	dpvs_sockopt_msg_free(result);
	return laddrs;
}

struct dp_vs_blklst_conf_array *ipvs_get_blklsts(void)
{
	struct dp_vs_blklst_conf_array *array, *result;
	size_t size;
	int i, err;

	ipvs_func = ipvs_get_blklsts;

	err = dpvs_getsockopt(SOCKOPT_GET_BLKLST_GETALL, NULL, 0, 
				(void **)&result, &size);
	if (err != 0)
		return NULL;
	if (size < sizeof(*result)
		|| size != sizeof(*result) + \
		result->naddr * sizeof(struct dp_vs_blklst_conf)) {
		dpvs_sockopt_msg_free(result);
		return NULL;
	}
	if (!(array = malloc(size)))
		return NULL;
	memcpy(array, result, sizeof(struct dp_vs_blklst_conf_array));
	for (i = 0; i < result->naddr; i++) {
		memcpy(&array->blklsts[i], &result->blklsts[i],
			sizeof(struct dp_vs_blklst_conf));
	}

	dpvs_sockopt_msg_free(result);
	return array;
}

struct dp_vs_whtlst_conf_array *ipvs_get_whtlsts(void)
{
	struct dp_vs_whtlst_conf_array *array, *result;
	size_t size;
	int i, err;

	ipvs_func = ipvs_get_whtlsts;

	err = dpvs_getsockopt(SOCKOPT_GET_WHTLST_GETALL, NULL, 0, 
				(void **)&result, &size);
	if (err != 0)
		return NULL;
	if (size < sizeof(*result)
		|| size != sizeof(*result) + \
		result->naddr * sizeof(struct dp_vs_whtlst_conf)) {
		dpvs_sockopt_msg_free(result);
		return NULL;
	}
	if (!(array = malloc(size)))
		return NULL;
	memcpy(array, result, sizeof(struct dp_vs_whtlst_conf_array));
	for (i = 0; i < result->naddr; i++) {
		memcpy(&array->whtlsts[i], &result->whtlsts[i],
			sizeof(struct dp_vs_whtlst_conf));
	}

	dpvs_sockopt_msg_free(result);
	return array;
}

void ipvs_free_service(ipvs_service_entry_t *p)
{
	free(p);
}

const char *ipvs_strerror(int err)
{
	unsigned int i;
	struct table_struct {
		void *func;
		int err;
		const char *message;
	} table [] = {
		{ ipvs_add_service, EEXIST, "Service already exists" },
		{ ipvs_add_service, ENOENT, "Scheduler or persistence engine not found" },
		{ ipvs_update_service, ESRCH, "No such service" },
		{ ipvs_update_service, ENOENT, "Scheduler or persistence engine not found" },
		{ ipvs_del_service, ESRCH, "No such service" },
		{ ipvs_zero_service, ESRCH, "No such service" },
		{ ipvs_add_dest, ESRCH, "Service not defined" },
		{ ipvs_add_dest, EEXIST, "Destination already exists" },
		{ ipvs_update_dest, ESRCH, "Service not defined" },
		{ ipvs_update_dest, ENOENT, "No such destination" },
		{ ipvs_del_dest, ESRCH, "Service not defined" },
		{ ipvs_del_dest, ENOENT, "No such destination" },
		{ ipvs_start_daemon, EEXIST, "Daemon has already run" },
		{ ipvs_stop_daemon, ESRCH, "No daemon is running" },
		{ ipvs_add_laddr, ESRCH, "Service not defined" },
		{ ipvs_add_laddr, EEXIST, "Local address already exists" },
		{ ipvs_del_laddr, ESRCH, "Service not defined" },
		{ ipvs_del_laddr, ENOENT, "No such Local address" },
		{ ipvs_get_laddrs, ESRCH, "Service not defined" },
		{ ipvs_add_blklst, ESRCH, "Service not defined" },
		{ ipvs_add_blklst, EEXIST, "blacklist address already exists" },
		{ ipvs_del_blklst, ESRCH, "Service not defined" },
		{ ipvs_del_blklst, ENOENT, "No such deny address" },
		{ ipvs_get_blklsts, ESRCH, "Service not defined" },
		{ ipvs_add_whtlst, ESRCH, "Service not defined" },
		{ ipvs_add_whtlst, EEXIST, "whitelist address already exists" },
		{ ipvs_del_whtlst, ESRCH, "Service not defined" },
		{ ipvs_del_whtlst, ENOENT, "No such deny address" },
		{ ipvs_get_whtlsts, ESRCH, "Service not defined" },
		{ ipvs_get_dests, ESRCH, "No such service" },
		{ ipvs_get_service, ESRCH, "No such service" },
		{ 0, EPERM, "Permission denied (you must be root)" },
		{ 0, EINVAL, "Invalid operation.  Possibly wrong module version, address not unicast, ..." },
		{ 0, ENOPROTOOPT, "Protocol not available" },
		{ 0, ENOMEM, "Memory allocation problem" },
		{ 0, EOPNOTSUPP, "Operation not supported with IPv6" },
		{ 0, EAFNOSUPPORT, "Operation not supported with specified address family" },
		{ 0, EMSGSIZE, "Module is wrong version" },
	};

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].func || table[i].func == ipvs_func)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}

