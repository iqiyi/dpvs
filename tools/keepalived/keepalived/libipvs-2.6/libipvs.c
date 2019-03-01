/*
 * libipvs:	Library for manipulating IPVS through [gs]etsockopt
 *
 * Version:     $Id: libipvs.c,v 1.7 2003/06/08 09:31:39 wensong Exp $
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "libipvs.h"
#include "sockopt.h"
#include "dp_vs.h"

typedef struct ipvs_servicedest_s {
	struct ip_vs_service_kern	svc;
	struct ip_vs_dest_kern		dest;
} ipvs_servicedest_t;

typedef struct ipvs_serviceladdr_s {
    struct ip_vs_service_kern   svc;
    struct ip_vs_laddr_kern     laddr;
} ipvs_serviceladdr_t;

static int sockfd = -1;
static void* ipvs_func = NULL;
struct ip_vs_getinfo ipvs_info;


#define CHECK_IPV4(s, ret) if (s->af && s->af != AF_INET)	\
	{ errno = EAFNOSUPPORT; goto out_err; }			\
	s->__addr_v4 = s->addr.ip;				\

#define CHECK_PE(s, ret) if (s->pe_name[0] != 0)		\
	{ errno = EAFNOSUPPORT; goto out_err; }

#define CHECK_COMPAT_DEST(s, ret) CHECK_IPV4(s, ret)

#define CHECK_COMPAT_SVC(s, ret)				\
	CHECK_IPV4(s, ret);					\
	CHECK_PE(s, ret);

#define CHECK_COMPAT_LADDR(s, ret) CHECK_IPV4(s, ret)

/* ipv6 support */
typedef struct dpvs_servicedest_s {
	struct dp_vs_service_user	svc;
	struct dp_vs_dest_user		dest; 
} dpvs_servicedest_t;

#define SVC_CONVERT(X, Y) {					\
	X->af               = Y->af; 				\
	memcpy(&X->addr, &Y->addr, sizeof(X->addr)); 		\
	X->port             = Y->port; 				\
	X->fwmark           = Y->fwmark; 			\
	snprintf(X->sched_name, IP_VS_SCHEDNAME_MAXLEN, "%s", Y->sched_name); \
	X->flags            = Y->flags; 			\
	X->timeout          = Y->timeout; 			\
	X->conn_timeout     = Y->conn_timeout; 			\
	X->netmask          = Y->netmask; 			\
	X->bps              = Y->bps; 				\
	X->limit_proportion = Y->limit_proportion; 		\
	snprintf(X->srange, sizeof(X->srange), "%s", Y->srange); \
	snprintf(X->drange, sizeof(X->drange), "%s", Y->drange); \
	snprintf(X->iifname, sizeof(X->iifname), "%s", Y->iifname); \
	snprintf(X->oifname, sizeof(X->oifname), "%s", Y->oifname);}

#define IPVS_2_DPVS(X, Y) {					\
	SVC_CONVERT(X, Y) 					\
	X->proto = Y->protocol;}

#define DPVS_2_IPVS(X, Y) {					\
	SVC_CONVERT(X, Y) 					\
	X->num_dests        = Y->num_dests;			\
	X->num_laddrs       = Y->num_laddrs;			\
	memcpy(&X->stats, &Y->stats, sizeof(X->stats));		\
	X->protocol = Y->proto;}

#define DST_CONVERT(X, Y) {					\
	X->af               = Y->af; 				\
	memcpy(&X->addr, &Y->addr, sizeof(X->addr)); 		\
	X->port             = Y->port; 				\
	X->conn_flags       = Y->conn_flags; 			\
	X->weight           = Y->weight;}

#define IPRS_2_DPRS(X, Y) {					\
	DST_CONVERT(X, Y) 					\
	X->max_conn         = Y->u_threshold; 			\
	X->min_conn         = Y->l_threshold;}

#define DPRS_2_IPRS(X, Y) {					\
	DST_CONVERT(X, Y)					\
	X->u_threshold      = Y->max_conn; 			\
	X->l_threshold      = Y->min_conn;			\
	X->activeconns      = Y->actconns;			\
	X->inactconns       = Y->inactconns;			\
	X->persistconns     = Y->persistconns;			\
	memcpy(&X->stats, &Y->stats, sizeof(X->stats));}

void ipvs_service_entry_2_user(const ipvs_service_entry_t *entry, ipvs_service_t *user);

int ipvs_init(void)
{
	socklen_t len;
	struct ip_vs_getinfo *ipvs_info_rcv;
	size_t len_rcv;

	ipvs_func = ipvs_init;
	len = sizeof(ipvs_info);
	len_rcv = len;

	if (dpvs_getsockopt(DPVS_SO_GET_INFO, (const void *)&ipvs_info, len,
                        (void **)&ipvs_info_rcv, &len_rcv))
		return -1;
	ipvs_info = *ipvs_info_rcv;
	dpvs_sockopt_msg_free(ipvs_info_rcv);
	return 0;
}


int ipvs_getinfo(void)
{
	socklen_t len;
	struct ip_vs_getinfo *ipvs_info_rcv;
	size_t len_rcv;

	ipvs_func = ipvs_getinfo;
	len = sizeof(ipvs_info);
	len_rcv = len;

	int ret = dpvs_getsockopt(DPVS_SO_GET_INFO, (const void *)&ipvs_info, len,
			       (void **)&ipvs_info_rcv, &len_rcv);
	ipvs_info = *ipvs_info_rcv;
	dpvs_sockopt_msg_free(ipvs_info_rcv);
	return ret;
}


unsigned int ipvs_version(void)
{
	return ipvs_info.version;
}


int ipvs_flush(void)
{
	return dpvs_setsockopt(DPVS_SO_SET_FLUSH, NULL, 0);
}


int ipvs_add_service(ipvs_service_t *svc)
{
	struct dp_vs_service_user dpvs_svc;
	struct dp_vs_service_user *dpvs_svc_ptr = &dpvs_svc;

	IPVS_2_DPVS(dpvs_svc_ptr, svc);

	return dpvs_setsockopt(DPVS_SO_SET_ADD, dpvs_svc_ptr, sizeof(dpvs_svc));
}


int ipvs_update_service(ipvs_service_t *svc)
{
	struct dp_vs_service_user dpvs_svc;
	struct dp_vs_service_user *dpvs_svc_ptr = &dpvs_svc;

	IPVS_2_DPVS(dpvs_svc_ptr, svc);

	return dpvs_setsockopt(DPVS_SO_SET_EDIT, dpvs_svc_ptr, sizeof(dpvs_svc));
}

int ipvs_update_service_by_options(ipvs_service_t *svc, unsigned int options)
{
	ipvs_service_entry_t *entry;
	ipvs_service_t user;

	if (!(entry = ipvs_get_service(svc))) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		exit(1);
	}
	ipvs_service_entry_2_user(entry, &user);

	if( options & OPT_SCHEDULER ) {
		strcpy(user.sched_name, svc->sched_name);
		if (strcmp(svc->sched_name, "conhash")) {
			user.flags &= ~IP_VS_SVC_F_QID_HASH;
			user.flags &= ~IP_VS_SVC_F_SIP_HASH;
		}
		else {
			user.flags |= IP_VS_SVC_F_SIP_HASH;
		}
	}

	if( options & OPT_PERSISTENT ) {
		user.flags  |= IP_VS_SVC_F_PERSISTENT;
		user.timeout = svc->timeout;
	}

	if( options & OPT_NETMASK ) {
		user.netmask = svc->netmask;
	}

	if( options & OPT_SYNPROXY ) {
		if( svc->flags & IP_VS_CONN_F_SYNPROXY ) {
			user.flags |= IP_VS_CONN_F_SYNPROXY;
		} else {
			user.flags &= ~IP_VS_CONN_F_SYNPROXY;
		}
	}

	if( options & OPT_ONEPACKET ) {
		user.flags |= IP_VS_SVC_F_ONEPACKET;
	}

	if( options & OPT_SIPHASH ) {
		user.flags |= IP_VS_SVC_F_SIP_HASH;
		user.flags &= ~IP_VS_SVC_F_QID_HASH;
	}

	if( options & OPT_QIDHASH ) {
		user.flags |= IP_VS_SVC_F_QID_HASH;
		user.flags &= ~IP_VS_SVC_F_SIP_HASH;
	}

	return ipvs_update_service(&user);
}

int ipvs_update_service_synproxy(ipvs_service_t *svc , int enable)
{
	ipvs_service_entry_t *entry;

	if (!(entry = ipvs_get_service(svc))) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		exit(1);
	}
	
	strcpy(svc->sched_name , entry->sched_name);
	strcpy(svc->pe_name , entry->pe_name);
	svc->flags = entry->flags;
	svc->timeout = entry->timeout;
	svc->conn_timeout = entry->conn_timeout;
	svc->netmask = entry->netmask;
	
	if(enable)
		svc->flags = svc->flags | IP_VS_CONN_F_SYNPROXY;
	else
		svc->flags = svc->flags & (~IP_VS_CONN_F_SYNPROXY);
	
	return 0;
}

int ipvs_del_service(ipvs_service_t *svc)
{
	struct dp_vs_service_user dpvs_svc;
	struct dp_vs_service_user *dpvs_svc_ptr = &dpvs_svc;

	IPVS_2_DPVS(dpvs_svc_ptr, svc);

	return dpvs_setsockopt(DPVS_SO_SET_DEL, dpvs_svc_ptr, sizeof(dpvs_svc));
}

int ipvs_zero_service(ipvs_service_t *svc)
{
	struct dp_vs_service_user dpvs_svc;
	struct dp_vs_service_user *dpvs_svc_ptr = &dpvs_svc;

	IPVS_2_DPVS(dpvs_svc_ptr, svc);

	return dpvs_setsockopt(DPVS_SO_SET_ZERO, dpvs_svc_ptr, sizeof(dpvs_svc));
}

int ipvs_add_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	dpvs_servicedest_t svcdest;
	struct dp_vs_service_user *dpvs_svc_ptr = &svcdest.svc;
	struct dp_vs_dest_user *dpvs_dest_ptr = &svcdest.dest;

	IPVS_2_DPVS(dpvs_svc_ptr, svc);
	IPRS_2_DPRS(dpvs_dest_ptr, dest);

	return dpvs_setsockopt(DPVS_SO_SET_ADDDEST, &svcdest, sizeof(svcdest));
}

int ipvs_update_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	dpvs_servicedest_t svcdest;
	struct dp_vs_service_user *dpvs_svc_ptr = &svcdest.svc;
	struct dp_vs_dest_user *dpvs_dest_ptr = &svcdest.dest;

	IPVS_2_DPVS(dpvs_svc_ptr, svc);
	IPRS_2_DPRS(dpvs_dest_ptr, dest);

	return dpvs_setsockopt(DPVS_SO_SET_EDITDEST, &svcdest, sizeof(svcdest));
}

int ipvs_del_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	dpvs_servicedest_t svcdest;
	struct dp_vs_service_user *dpvs_svc_ptr = &svcdest.svc;
	struct dp_vs_dest_user *dpvs_dest_ptr = &svcdest.dest;

	IPVS_2_DPVS(dpvs_svc_ptr, svc);
	IPRS_2_DPRS(dpvs_dest_ptr, dest);

	return dpvs_setsockopt(DPVS_SO_SET_DELDEST, &svcdest, sizeof(svcdest)); 
}

static void ipvs_fill_laddr_conf(ipvs_service_t *svc, ipvs_laddr_t *laddr, 
                                 struct dp_vs_laddr_conf *conf)
{
	memset(conf, 0, sizeof(*conf));
	conf->af_s      = svc->af;
	conf->proto     = svc->protocol;
	conf->vport     = svc->port;
	conf->fwmark    = svc->fwmark;
	conf->af_l      = laddr->af;
	if (strlen(laddr->ifname))
		snprintf(conf->ifname, sizeof(conf->ifname), "%s", laddr->ifname);

	if (svc->af == AF_INET) {
		conf->vaddr.in = svc->addr.in;
	} else {
		conf->vaddr.in6 = svc->addr.in6;
	}

	if (laddr->af == AF_INET) {
		conf->laddr.in = laddr->addr.in;
	} else {
		conf->laddr.in6 = laddr->addr.in6;
	}

	return;
}

static void ipvs_fill_ipaddr_conf(ipvs_laddr_t *laddr, struct inet_addr_param *param)
{
	memset(param, 0, sizeof(*param));
	param->af = laddr->af;
	if (strlen(laddr->ifname))
		snprintf(param->ifname, sizeof(param->ifname), "%s", laddr->ifname);
	if (laddr->af == AF_INET) {
		param->addr.in = laddr->addr.in;
		param->plen = 32;
	} else {
		param->plen = 128;
		param->addr.in6 = laddr->addr.in6;
	}
	param->flags |= IFA_F_SAPOOL;
	return;
}

int ipvs_add_laddr(ipvs_service_t *svc, ipvs_laddr_t *laddr)
{
	struct dp_vs_laddr_conf conf;
	struct inet_addr_param param;

	ipvs_fill_laddr_conf(svc, laddr, &conf);
	ipvs_fill_ipaddr_conf(laddr, &param);
	ipvs_set_ipaddr(&param, 1);

	return dpvs_setsockopt(SOCKOPT_SET_LADDR_ADD, &conf, sizeof(conf));
}

int ipvs_del_laddr(ipvs_service_t *svc, ipvs_laddr_t *laddr)
{
	struct dp_vs_laddr_conf conf;
	struct inet_addr_param param;

	ipvs_fill_laddr_conf(svc, laddr, &conf);
	ipvs_fill_ipaddr_conf(laddr, &param);
	ipvs_set_ipaddr(&param, 0);

	return dpvs_setsockopt(SOCKOPT_SET_LADDR_DEL, &conf, sizeof(conf));
}

/*for black list*/
static void ipvs_fill_blklst_conf(ipvs_service_t *svc, ipvs_blklst_t *blklst,
                                 struct dp_vs_blklst_conf *conf)
{
	memset(conf, 0, sizeof(*conf));
	conf->af        = svc->af;
	conf->proto     = svc->protocol;
	conf->vport     = svc->port;
	conf->fwmark    = svc->fwmark;
	if (svc->af == AF_INET) {
		conf->vaddr.in = svc->addr.in;
		conf->blklst.in = blklst->addr.in;
	} else {
		conf->vaddr.in6 = svc->addr.in6;
		conf->blklst.in6 = blklst->addr.in6;
	}

	return;
}

int ipvs_add_blklst(ipvs_service_t *svc, ipvs_blklst_t *blklst)
{
	struct dp_vs_blklst_conf conf;

	ipvs_fill_blklst_conf(svc, blklst, &conf);

	return dpvs_setsockopt(SOCKOPT_SET_BLKLST_ADD, &conf, sizeof(conf));
}

int ipvs_del_blklst(ipvs_service_t *svc, ipvs_blklst_t * blklst)
{
	struct dp_vs_blklst_conf conf;

	ipvs_fill_blklst_conf(svc, blklst, &conf);

	return dpvs_setsockopt(SOCKOPT_SET_BLKLST_DEL, &conf, sizeof(conf));
}

/* for tunnel entry */
static void ipvs_fill_tunnel_conf(ipvs_tunnel_t* tunnel_entry,
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

int ipvs_add_tunnel(ipvs_tunnel_t* tunnel_entry)
{
	struct ip_tunnel_param conf;
	ipvs_fill_tunnel_conf(tunnel_entry, &conf);
	ipvs_func = ipvs_add_tunnel;
	return dpvs_setsockopt(SOCKOPT_TUNNEL_ADD, &conf, sizeof(conf));
}

int ipvs_del_tunnel(ipvs_tunnel_t* tunnel_entry)
{
	struct ip_tunnel_param conf;
	ipvs_fill_tunnel_conf(tunnel_entry, &conf);
	ipvs_func = ipvs_del_tunnel;
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
			  (char *)dm, sizeof(*dm));
}


int ipvs_stop_daemon(ipvs_daemon_t *dm)
{
	ipvs_func = ipvs_stop_daemon;

	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STOPDAEMON,
			  (char *)dm, sizeof(*dm));
}


struct ip_vs_get_services *ipvs_get_services(void)
{
	struct ip_vs_get_services *get;
	struct dp_vs_get_services *dpvs_get, *dpvs_get_rcv;
	struct dp_vs_service_entry *dpvs_entry;
	struct ip_vs_service_entry *ipvs_entry;
	size_t len = 0, len_rcv = 0;
	int i;

	len = sizeof(struct ip_vs_get_services) +
		sizeof(ipvs_service_entry_t) * ipvs_info.num_services;
	if (!(get = calloc(len, 1)))
		return NULL;

	len = sizeof(struct dp_vs_get_services);
	if (!(dpvs_get = calloc(len, 1))) {
		free(get);
		return NULL;
	}
	dpvs_get->num_services = ipvs_info.num_services;
	
	if (dpvs_getsockopt(DPVS_SO_GET_SERVICES, dpvs_get, len, (void **)&dpvs_get_rcv, &len_rcv)) {
		free(get);
		free(dpvs_get);
		return NULL;
	}

	get->num_services = dpvs_get_rcv->num_services;
	for (i = 0; i < dpvs_get_rcv->num_services; i++) {
		ipvs_entry = &get->entrytable[i];
		dpvs_entry = &dpvs_get_rcv->entrytable[i];
		DPVS_2_IPVS(ipvs_entry, dpvs_entry);
		if (dpvs_get_rcv->entrytable[i].af == AF_INET) {
			get->entrytable[i].__addr_v4 = get->entrytable[i].addr.ip;
			get->entrytable[i].pe_name[0] = '\0';
		}
	}

	free(dpvs_get);
	dpvs_sockopt_msg_free(dpvs_get_rcv);
	return get;
}


void ipvs_free_services(struct ip_vs_get_services * p)
{
	free(p);
}


typedef int (*qsort_cmp_t)(const void *, const void *);

int
ipvs_cmp_services(ipvs_service_entry_t *s1, ipvs_service_entry_t *s2)
{
	int r, i;

	r = s1->fwmark - s2->fwmark;
	if (r != 0)
		return r;

	r = s1->af - s2->af;
	if (r != 0)
		return r;

	r = s1->protocol - s2->protocol;
	if (r != 0)
		return r;

	if (s1->af == AF_INET6)
		for (i = 0; !r && (i < 4); i++)
			r = ntohl(s1->addr.in6.s6_addr32[i]) - ntohl(s2->addr.in6.s6_addr32[i]);
	else
		r = ntohl(s1->addr.ip) - ntohl(s2->addr.ip);
	if (r != 0)
		return r;

	return ntohs(s1->port) - ntohs(s2->port);
}

struct ip_vs_conn_array* ip_vs_get_conns(const struct ip_vs_conn_req *req) {
    int res;
    size_t arrlen, rcvlen;
    struct ip_vs_conn_array *conn_arr, *arr_rcv;

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

void
ipvs_sort_services(struct ip_vs_get_services *s, ipvs_service_cmp_t f)
{
	qsort(s->entrytable, s->num_services,
	      sizeof(ipvs_service_entry_t), (qsort_cmp_t)f);
}

struct ip_vs_get_laddrs *ipvs_get_laddrs(ipvs_service_entry_t *svc)
{
	struct ip_vs_get_laddrs *laddrs;
	struct dp_vs_laddr_conf conf, *result;
	size_t res_size, i;

	memset(&conf, 0, sizeof(struct dp_vs_laddr_conf));
	conf.af_s = svc->af;
	conf.proto = svc->protocol;
	if (svc->af == AF_INET)
		conf.vaddr.in = svc->addr.in;
	else
		conf.vaddr.in6 = svc->addr.in6;
	conf.vport = svc->port;
	conf.fwmark = svc->fwmark;

	snprintf(conf.srange, sizeof(conf.srange), "%s", svc->srange);
	snprintf(conf.drange, sizeof(conf.drange), "%s", svc->drange);
	snprintf(conf.iifname, sizeof(conf.iifname), "%s", svc->iifname);
	snprintf(conf.iifname, sizeof(conf.oifname), "%s", svc->oifname);

	if (dpvs_getsockopt(SOCKOPT_GET_LADDR_GETALL, &conf, sizeof(conf),
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


void ipvs_free_lddrs(struct ip_vs_get_laddrs* p)
{
	free(p);
}

struct dp_vs_blklst_conf_array *ipvs_get_blklsts(void)
{
	struct dp_vs_blklst_conf_array *array, *result;
	size_t size;
	int i, err;

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

struct ip_vs_get_dests *ipvs_get_dests(ipvs_service_entry_t *svc)
{
	struct ip_vs_get_dests *d;
	struct dp_vs_get_dests *dpvs_dests, *dpvs_dests_rcv;
	struct ip_vs_dest_entry *ipvs_entry;
	struct dp_vs_dest_entry *dpvs_entry;
	size_t len = 0, len_rcv = 0;
	int i;

	len = sizeof(struct ip_vs_get_dests) + 
		sizeof(ipvs_dest_entry_t) * svc->num_dests;
	if (!(d = calloc(len, 1)))
		return NULL;

	len = sizeof(struct dp_vs_get_dests);
	if (!(dpvs_dests = calloc(len, 1))) {
		free(d);
		return NULL;
	}

	dpvs_dests->af = svc->af;
	dpvs_dests->fwmark = svc->fwmark;
	dpvs_dests->proto = svc->protocol;
	memcpy(&dpvs_dests->addr, &svc->addr, sizeof(svc->addr));
	dpvs_dests->port = svc->port;
	dpvs_dests->num_dests = svc->num_dests;
	snprintf(dpvs_dests->srange, sizeof(dpvs_dests->srange), "%s", svc->srange);
	snprintf(dpvs_dests->drange, sizeof(dpvs_dests->drange), "%s", svc->drange);
	snprintf(dpvs_dests->iifname, sizeof(dpvs_dests->iifname), "%s", svc->iifname);
	snprintf(dpvs_dests->oifname, sizeof(dpvs_dests->oifname), "%s", svc->oifname);

	if (dpvs_getsockopt(DPVS_SO_GET_DESTS, dpvs_dests, len, (void **)&dpvs_dests_rcv, &len_rcv)) {
		free(d);
		free(dpvs_dests);
		return NULL;
	}

	d->af = dpvs_dests_rcv->af;
	memcpy(&d->addr, &dpvs_dests_rcv->addr, sizeof(d->addr));
	d->protocol  = dpvs_dests_rcv->proto;
	d->port = dpvs_dests_rcv->port;
	d->fwmark = dpvs_dests_rcv->fwmark;
	d->num_dests = dpvs_dests_rcv->num_dests;
	snprintf(d->srange, sizeof(dpvs_dests_rcv->srange), "%s", dpvs_dests_rcv->srange);
	snprintf(d->drange, sizeof(dpvs_dests_rcv->drange), "%s", dpvs_dests_rcv->drange);
	snprintf(d->iifname, sizeof(dpvs_dests_rcv->iifname), "%s", dpvs_dests_rcv->iifname);
	snprintf(d->oifname, sizeof(dpvs_dests_rcv->oifname), "%s", dpvs_dests_rcv->oifname);
	if (d->af == AF_INET) {
		d->__addr_v4 = d->addr.ip;
	}
	for (i = 0; i < dpvs_dests_rcv->num_dests; i++) {
		ipvs_entry = &d->entrytable[i];
		dpvs_entry = &dpvs_dests_rcv->entrytable[i];
		DPRS_2_IPRS(ipvs_entry, dpvs_entry);
		if (d->entrytable[i].af == AF_INET)
			d->entrytable[i].__addr_v4= d->entrytable[i].addr.ip;
	}
	free(dpvs_dests);	
	dpvs_sockopt_msg_free(dpvs_dests_rcv);
	return d;
}


int ipvs_cmp_dests(ipvs_dest_entry_t *d1, ipvs_dest_entry_t *d2)
{
	int r = 0, i;

	if (d1->af == AF_INET6)
		for (i = 0; !r && (i < 4); i++)
			r = ntohl(d1->addr.in6.s6_addr32[i]) -
			    ntohl(d2->addr.in6.s6_addr32[i]);
	else
		r = ntohl(d1->addr.ip) - ntohl(d2->addr.ip);
	if (r != 0)
		return r;

	return ntohs(d1->port) - ntohs(d2->port);
}


void ipvs_sort_dests(struct ip_vs_get_dests *d, ipvs_dest_cmp_t f)
{
	qsort(d->entrytable, d->num_dests,
	      sizeof(ipvs_dest_entry_t), (qsort_cmp_t)f);
}


ipvs_service_entry_t *
ipvs_get_service(struct ip_vs_service_user *hint)
{
	ipvs_service_entry_t *svc;
	struct dp_vs_service_entry dpvs_svc, *dpvs_svc_ptr, *dpvs_svc_rcv;
	socklen_t len;
	size_t len_rcv;

	len = sizeof(*svc);
	svc = calloc(1, len);
	if (!svc)
		return NULL;
	memset((void *)svc, 0x00, len);

	len = sizeof(dpvs_svc);
	len_rcv = sizeof(*dpvs_svc_rcv);
	memset(&dpvs_svc, 0, len);
	dpvs_svc_ptr = &dpvs_svc;
	IPVS_2_DPVS(dpvs_svc_ptr, hint);

	if (dpvs_getsockopt(DPVS_SO_GET_SERVICE,
		       &dpvs_svc, len, (void **)&dpvs_svc_rcv, &len_rcv)) {
		goto out_err;
	}

	DPVS_2_IPVS(svc, dpvs_svc_rcv)
	if (svc->af == AF_INET) {
		svc->pe_name[0] = '\0';
		svc->__addr_v4 = svc->addr.ip;
	}
	dpvs_sockopt_msg_free(dpvs_svc_rcv);
	return svc;
out_err:
	free(svc);
	return NULL;
}


void ipvs_free_service(ipvs_service_entry_t* p)
{
	free(p);
}

int ipvs_set_route(struct dp_vs_route_conf *rt, int cmd)
{
    int err = -1;
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
   if (cmd == IPADDRESS_DEL)
       err = dpvs_setsockopt(SOCKOPT_SET_IFADDR_DEL, param, sizeof(struct inet_addr_param)); 
   else if (cmd == IPADDRESS_ADD)
       err = dpvs_setsockopt(SOCKOPT_SET_IFADDR_ADD, param, sizeof(struct inet_addr_param));
   return err;
}

int ipvs_send_gratuitous_arp(struct in_addr *in)
{
    return dpvs_setsockopt(DPVS_SO_SET_GRATARP, in, sizeof(in));
}

ipvs_timeout_t *ipvs_get_timeout(void)
{
	ipvs_timeout_t *u;
	socklen_t len;

	len = sizeof(*u);
	if (!(u = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_timeout;
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_TIMEOUT,
		       (char *)u, &len)) {
		free(u);
		return NULL;
	}
	//return u;
    return NULL;
}


ipvs_daemon_t *ipvs_get_daemon(void)
{
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
	//return u;
    return NULL;
}


void ipvs_close(void)
{
    //close(sockfd);
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
		{ ipvs_get_services, ESRCH, "No such service" },
		{ ipvs_get_dests, ESRCH, "No such service" },
		{ ipvs_get_service, ESRCH, "No such service" },
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


void ipvs_service_entry_2_user(const ipvs_service_entry_t *entry, ipvs_service_t *user)
{
	user->protocol  = entry->protocol;
	user->__addr_v4 = entry->__addr_v4;
	user->port      = entry->port;
	user->fwmark    = entry->fwmark;
	strcpy(user->sched_name, entry->sched_name);
	user->flags     = entry->flags;
	user->timeout   = entry->timeout;
	user->conn_timeout = entry->conn_timeout;
	user->netmask   = entry->netmask;
	user->af        = entry->af;
	user->addr      = entry->addr;
	strcpy(user->pe_name, entry->pe_name);
	strcpy(user->srange, entry->srange);
	strcpy(user->drange, entry->drange);
	strcpy(user->iifname, entry->iifname);
	strcpy(user->iifname, entry->iifname);
}

