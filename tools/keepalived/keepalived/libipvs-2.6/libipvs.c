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
	ipvs_func = ipvs_add_service;
	CHECK_COMPAT_SVC(svc, -1);
	return dpvs_setsockopt(DPVS_SO_SET_ADD, (const void *)svc, sizeof(struct ip_vs_service_kern));
out_err:
	return -1;
}


int ipvs_update_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_update_service;
	CHECK_COMPAT_SVC(svc, -1);
	return dpvs_setsockopt(DPVS_SO_SET_EDIT, (const void *)svc, sizeof(struct ip_vs_service_kern));
out_err:
	return -1;
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
	ipvs_func = ipvs_del_service;
	CHECK_COMPAT_SVC(svc, -1);
	return dpvs_setsockopt(DPVS_SO_SET_DEL, (const void *)svc, sizeof(struct ip_vs_service_kern));
out_err:
	return -1;
}


int ipvs_zero_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_zero_service;
	CHECK_COMPAT_SVC(svc, -1);
	return dpvs_setsockopt(DPVS_SO_SET_ZERO, (const void *)svc, sizeof(struct ip_vs_service_kern));
out_err:
	return -1;
}


int ipvs_add_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_servicedest_t svcdest;
	ipvs_func = ipvs_add_dest;

	CHECK_COMPAT_SVC(svc, -1);
	CHECK_COMPAT_DEST(dest, -1);
	memcpy(&svcdest.svc, svc, sizeof(svcdest.svc));
	memcpy(&svcdest.dest, dest, sizeof(svcdest.dest));
	return dpvs_setsockopt(DPVS_SO_SET_ADDDEST, &svcdest, sizeof(svcdest));
out_err:
	return -1;
}


int ipvs_update_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_servicedest_t svcdest;

	ipvs_func = ipvs_update_dest;
	CHECK_COMPAT_SVC(svc, -1);
	CHECK_COMPAT_DEST(dest, -1);
	memcpy(&svcdest.svc, svc, sizeof(svcdest.svc));
	memcpy(&svcdest.dest, dest, sizeof(svcdest.dest));
	return dpvs_setsockopt(DPVS_SO_SET_EDITDEST, &svcdest, sizeof(svcdest));
out_err:
	return -1;
}


int ipvs_del_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_servicedest_t svcdest;

	ipvs_func = ipvs_del_dest;

	CHECK_COMPAT_SVC(svc, -1);
	CHECK_COMPAT_DEST(dest, -1);
	memcpy(&svcdest.svc, svc, sizeof(svcdest.svc));
	memcpy(&svcdest.dest, dest, sizeof(svcdest.dest));
	return dpvs_setsockopt(DPVS_SO_SET_DELDEST, &svcdest, sizeof(svcdest)); 
out_err:
	return -1;
}

static void ipvs_fill_laddr_conf(ipvs_service_t *svc, ipvs_laddr_t *laddr, 
                                 struct dp_vs_laddr_conf *conf)
{
	memset(conf, 0, sizeof(*conf));
	conf->af        = svc->af;
	conf->proto     = svc->protocol;
	conf->vport     = svc->port;
	conf->fwmark    = svc->fwmark;
	if (strlen(laddr->ifname))
		snprintf(conf->ifname, sizeof(conf->ifname), "%s", laddr->ifname);
	if (svc->af == AF_INET) {
		conf->vaddr.in = svc->addr.in;
		conf->laddr.in = laddr->addr.in;
	} else {
		conf->vaddr.in6 = svc->addr.in6;
		conf->laddr.in6 = laddr->addr.in6;
	}    

	return;
}

static void ipvs_fill_ipaddr_conf(ipvs_laddr_t *laddr, struct inet_addr_param *param)
{
	memset(param, 0, sizeof(*param));
	param->af = AF_INET;
	if (strlen(laddr->ifname))
		snprintf(param->ifname, sizeof(param->ifname), "%s", laddr->ifname);
	param->addr.in = laddr->addr.in;
	param->plen = 32;
	param->flags |= IFA_F_SAPOOL;
	return;
}

int ipvs_add_laddr(ipvs_service_t *svc, ipvs_laddr_t * laddr)
{
	struct dp_vs_laddr_conf conf;
	struct inet_addr_param param;

	ipvs_fill_laddr_conf(svc, laddr, &conf);
	ipvs_fill_ipaddr_conf(laddr, &param);
	ipvs_set_ipaddr(&param, 1);

	return dpvs_setsockopt(SOCKOPT_SET_LADDR_ADD, &conf, sizeof(conf));
}

int ipvs_del_laddr(ipvs_service_t *svc, ipvs_laddr_t * laddr)
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
	struct ip_vs_get_services_kern *getk,*getk_rcv;
	size_t len, len_rcv;
	int i;


	len = sizeof(*get) +
		sizeof(ipvs_service_entry_t) * ipvs_info.num_services;
	if (!(get = calloc(len, 1)))
		return NULL;
	len = sizeof(*getk) +
		sizeof(struct ip_vs_service_entry_kern) * ipvs_info.num_services;
	if (!(getk = malloc(len))) {
		free(get);
		return NULL;
	}

	ipvs_func = ipvs_get_services;
	getk->num_services = ipvs_info.num_services;
	len_rcv = len;
	if (dpvs_getsockopt(DPVS_SO_GET_SERVICES, getk, len, (void **)&getk_rcv, &len_rcv) < 0) {
		free(get);
		free(getk);
        //dpvs_sockopt_msg_free(getk_rcv);
		return NULL;
	}
	memcpy(get, getk_rcv, sizeof(struct ip_vs_get_services));
	for (i = 0; i < getk_rcv->num_services; i++) {
		memcpy(&get->entrytable[i], &getk_rcv->entrytable[i],
		       sizeof(struct ip_vs_service_entry_kern));
		get->entrytable[i].af = AF_INET;
		get->entrytable[i].addr.ip = get->entrytable[i].__addr_v4;
	}
	free(getk);
	dpvs_sockopt_msg_free(getk_rcv);
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
	conf.af = svc->af;
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
	laddrs->af = result->af;
	if (result->af == AF_INET)
		laddrs->addr.in = result->vaddr.in;
	else
		laddrs->addr.in6 = result->vaddr.in6;

	for (i = 0; i < result->nladdrs; i++) {
		laddrs->entrytable[i].__addr_v4 = result->laddrs[i].addr.in.s_addr;
		laddrs->entrytable[i].port_conflict = result->laddrs[i].nport_conflict;
		laddrs->entrytable[i].conn_counts = result->laddrs[i].nconns;
		laddrs->entrytable[i].af = result->af;
		if (result->af == AF_INET)
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
	struct ip_vs_get_dests_kern *dk, *dk_rcv;
	size_t len, len_rcv;
	int i;

	len = sizeof(*d) + sizeof(ipvs_dest_entry_t) * svc->num_dests;
	if (!(d = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_dests;

	if (svc->af != AF_INET) {
	  errno = EAFNOSUPPORT;
	  free(d);
	  return NULL;
	}

	len = sizeof(*dk) + sizeof(struct ip_vs_dest_entry_kern) * svc->num_dests;
	if (!(dk = malloc(len))) {
		free(d);
		return NULL;
	}

	dk->fwmark = svc->fwmark;
	dk->protocol = svc->protocol;
	dk->addr = svc->addr.ip;
	dk->port = svc->port;
	dk->num_dests = svc->num_dests;
	snprintf(dk->srange, sizeof(dk->srange), "%s", svc->srange);
	snprintf(dk->drange, sizeof(dk->drange), "%s", svc->drange);
	snprintf(dk->iifname, sizeof(dk->iifname), "%s", svc->iifname);
	snprintf(dk->oifname, sizeof(dk->oifname), "%s", svc->oifname);

	if (dpvs_getsockopt(DPVS_SO_GET_DESTS, dk, len, (void **)&dk_rcv, &len_rcv) < 0) {
		free(d);
		free(dk);
        dpvs_sockopt_msg_free(dk_rcv);
		return NULL;
	}
	memcpy(d, dk_rcv, sizeof(struct ip_vs_get_dests_kern));
	d->af = AF_INET;
	d->addr.ip = d->__addr_v4;
	for (i = 0; i < dk_rcv->num_dests; i++) {
		memcpy(&d->entrytable[i], &dk_rcv->entrytable[i],
		       sizeof(struct ip_vs_dest_entry_kern));
		d->entrytable[i].af = AF_INET;
		d->entrytable[i].addr.ip = d->entrytable[i].__addr_v4;
	}
	free(dk);
	dpvs_sockopt_msg_free(dk_rcv);
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
	ipvs_service_entry_t *svc,*svc_rcv;
	socklen_t len;
	size_t len_rcv;

	ipvs_func = ipvs_get_service;

	len = sizeof(*svc);
	svc = calloc(1, len);
	if (!svc)
		return NULL;
	len_rcv = len;
	memset((void *)svc, 0x00, len);

	svc->fwmark = hint->fwmark;
	svc->af = hint->af;
	svc->protocol = hint->protocol;
	svc->addr = hint->addr;
	svc->port = hint->port;
	snprintf(svc->srange, sizeof(svc->srange), "%s", hint->srange);
	snprintf(svc->drange, sizeof(svc->drange), "%s", hint->drange);
	snprintf(svc->iifname, sizeof(svc->iifname), "%s", hint->iifname);
	snprintf(svc->oifname, sizeof(svc->oifname), "%s", hint->oifname);

	CHECK_COMPAT_SVC(svc, NULL);
	if (dpvs_getsockopt(DPVS_SO_GET_SERVICE,
		       svc, len, (void **)&svc_rcv, &len_rcv)) {
		free(svc);
		dpvs_sockopt_msg_free(svc_rcv);
		return NULL;
	}
	memcpy(svc, svc_rcv, len_rcv);
	svc->af = AF_INET;
	svc->addr.ip = svc->__addr_v4;
	svc->pe_name[0] = '\0';
	dpvs_sockopt_msg_free(svc_rcv);
	return svc;
out_err:
	free(svc);
	dpvs_sockopt_msg_free(svc_rcv);
	return NULL;
}


void ipvs_free_service(ipvs_service_entry_t* p)
{
	free(p);
}

int ipvs_set_route(struct dp_vs_route_conf* rt, int cmd)
{
    int err = -1;
    if (cmd == IPROUTE_DEL){
        err = dpvs_setsockopt(SOCKOPT_SET_ROUTE_DEL, rt, sizeof(struct dp_vs_route_conf));
        free(rt);
    }
    else if (cmd == IPROUTE_ADD){
        err = dpvs_setsockopt(SOCKOPT_SET_ROUTE_ADD, rt, sizeof(struct dp_vs_route_conf));
        free(rt);
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
}

