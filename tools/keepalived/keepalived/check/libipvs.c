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
#include <assert.h>

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
static void* dpvs_ctrl_func = NULL;

typedef struct dpvs_servicedest_s {
    dpvs_service_compat_t dpvs_svc;
    dpvs_dest_compat_t dpvs_dest;
} dpvs_servicedest_t;

typedef struct dp_vs_service_entry_app {
    struct dp_vs_service_entry user;
} dpvs_service_entry_t;

struct ip_vs_getinfo g_ipvs_info;

int dpvs_ctrl_init(lcoreid_t cid)
{
    //socklen_t len, len_rcv;
    size_t len, len_rcv;
    struct ip_vs_getinfo *ipvs_info_rcv;

    dpvs_ctrl_func = dpvs_ctrl_init;

	dpvs_sockopt_init();

#if !HAVE_DECL_SOCK_CLOEXEC
    if (set_sock_flags(sockfd, F_SETFD, FD_CLOEXEC)) {
        close(sockfd);
        return -1;
    }
#endif
    len = sizeof(g_ipvs_info);
    len_rcv = len;

    if (ESOCKOPT_OK != dpvs_getsockopt(DPVS_SO_GET_INFO,
                (const void*)&g_ipvs_info,
                len,
                (void **)&ipvs_info_rcv,
                &len_rcv)) {
        return -1;
    }

    memcpy(&g_ipvs_info, ipvs_info_rcv, sizeof(g_ipvs_info));

    dpvs_sockopt_msg_free(ipvs_info_rcv);

    return 0;
}

int dpvs_flush(void)
{
    return dpvs_setsockopt(DPVS_SO_SET_FLUSH, NULL, 0);
}

int dpvs_add_service(dpvs_service_compat_t *svc)
{
    dpvs_ctrl_func = dpvs_add_service;

    return dpvs_setsockopt(DPVS_SO_SET_ADD, svc, sizeof(dpvs_service_compat_t));
}

int dpvs_update_service(dpvs_service_compat_t *svc)
{
    dpvs_ctrl_func = dpvs_update_service;

    return dpvs_setsockopt(DPVS_SO_SET_EDIT, svc, sizeof(dpvs_service_compat_t));
}


int dpvs_update_service_by_options(dpvs_service_compat_t *svc, unsigned int options)
{
    dpvs_service_compat_t entry;

    if (!dpvs_get_service(svc, &entry)) {
        fprintf(stderr, "%s\n", ipvs_strerror(errno));
        return ESOCKOPT_INVAL;
    }

    if (options & OPT_SCHEDULER) {
        strcpy(entry.sched_name, svc->sched_name);
        if (strcmp(svc->sched_name, "conhash")) {
            entry.flags &= ~IP_VS_SVC_F_QID_HASH;
            entry.flags &= ~IP_VS_SVC_F_SIP_HASH;
        } else {
            entry.flags |= IP_VS_SVC_F_SIP_HASH;
        }
    }

    if (options & OPT_PERSISTENT) {
        entry.flags  |= IP_VS_SVC_F_PERSISTENT;
        entry.timeout = svc->timeout;
    }
    entry.conn_timeout = svc->conn_timeout;
    entry.proxy_protocol = svc->proxy_protocol;

    if (options & OPT_NETMASK) {
        entry.netmask = svc->netmask;
    }

    if (options & OPT_SYNPROXY) {
        if(svc->flags & IP_VS_SVC_F_SYNPROXY) {
            entry.flags |= IP_VS_SVC_F_SYNPROXY;
        } else {
            entry.flags &= ~IP_VS_SVC_F_SYNPROXY;
        }
    }

    if (options & OPT_EXPIRE_QUIESCENT_CONN) {
        if (svc->flags & IP_VS_SVC_F_EXPIRE_QUIESCENT) {
            entry.flags |= IP_VS_SVC_F_EXPIRE_QUIESCENT;
        } else {
            entry.flags &= ~IP_VS_SVC_F_EXPIRE_QUIESCENT;
        }
    }

    if (options & OPT_ONEPACKET) {
        entry.flags |= IP_VS_SVC_F_ONEPACKET;
    }

    if (options & OPT_HASHTAG) {
        entry.flags &= ~ IP_VS_SVC_F_QID_HASH;
        entry.flags &= ~ IP_VS_SVC_F_SIP_HASH;
        if (svc->flags & IP_VS_SVC_F_SIP_HASH) {
            entry.flags |= IP_VS_SVC_F_SIP_HASH;
        } else if (svc->flags & IP_VS_SVC_F_QID_HASH) {
            entry.flags |= IP_VS_SVC_F_QID_HASH;
        } else {
            entry.flags |= IP_VS_SVC_F_SIP_HASH;
        }
    }

    if (dest_check_configs_sanity(&svc->check_conf))
        entry.check_conf = svc->check_conf;

    return dpvs_update_service(&entry);
}

int dpvs_del_service(dpvs_service_compat_t *dpvs_svc)
{
    dpvs_ctrl_func = dpvs_del_service;

    return dpvs_setsockopt(DPVS_SO_SET_DEL, dpvs_svc, sizeof(dpvs_service_compat_t));
}

int dpvs_zero_service(dpvs_service_compat_t *svc)
{
    dpvs_ctrl_func = dpvs_zero_service;

    return dpvs_setsockopt(DPVS_SO_SET_ZERO, svc, sizeof(dpvs_service_compat_t));
}

int dpvs_add_dest(dpvs_service_compat_t *svc, dpvs_dest_compat_t *dest)
{
    dpvs_servicedest_t svcdest;
    int len_svc, len_dest;

    dpvs_ctrl_func = dpvs_add_dest;

    memcpy(&svcdest.dpvs_svc, svc, sizeof(dpvs_service_compat_t));
    memcpy(&svcdest.dpvs_dest, dest, sizeof(dpvs_dest_compat_t));

    return dpvs_setsockopt(DPVS_SO_SET_ADDDEST, &svcdest, sizeof(svcdest));
}

int dpvs_update_dest(dpvs_service_compat_t *svc, dpvs_dest_compat_t *dest)
{
    dpvs_servicedest_t svcdest;

    dpvs_ctrl_func = dpvs_update_dest;

    memcpy(&svcdest.dpvs_svc, svc, sizeof(dpvs_service_compat_t));
    memcpy(&svcdest.dpvs_dest, dest, sizeof(dpvs_dest_compat_t));

    return dpvs_setsockopt(DPVS_SO_SET_EDITDEST, &svcdest, sizeof(svcdest));
}

int dpvs_del_dest(dpvs_service_compat_t *svc, dpvs_dest_compat_t *dest)
{
    dpvs_servicedest_t svcdest;

    dpvs_ctrl_func = dpvs_del_dest;

    memcpy(&svcdest.dpvs_svc, svc, sizeof(dpvs_service_compat_t));
    memcpy(&svcdest.dpvs_dest, dest, sizeof(dpvs_dest_compat_t));

    return dpvs_setsockopt(DPVS_SO_SET_DELDEST, &svcdest, sizeof(svcdest));
}

static void dpvs_fill_laddr_conf(dpvs_service_compat_t *svc, dpvs_laddr_table_t *laddr)
{
    laddr->af_s      = svc->af;
    laddr->proto     = svc->proto;
    laddr->vport     = svc->port;
    laddr->fwmark    = svc->fwmark;

    if (svc->af == AF_INET) {
        laddr->vaddr.in = svc->addr.in;
    } else {
        laddr->vaddr.in6 = svc->addr.in6;
    }

    return ;
}

static void dpvs_fill_ipaddr_conf(int is_add, uint32_t flags,
        dpvs_laddr_table_t *laddrs, struct inet_addr_param *param)
{
    memset(param, 0, sizeof(*param));

    if (is_add)
        param->ifa_ops = INET_ADDR_ADD;
    else
        param->ifa_ops = INET_ADDR_DEL;
    param->ifa_ops_flags = flags;
    param->ifa_entry.af = laddrs->af_l;
    if (strlen(laddrs->ifname))
        snprintf(param->ifa_entry.ifname, sizeof(param->ifa_entry.ifname), "%s", laddrs->ifname);
    if (laddrs->af_l == AF_INET) {
        param->ifa_entry.addr.in = laddrs->laddr.in;
        param->ifa_entry.plen = 32;
    } else {
        param->ifa_entry.plen = 128;
        param->ifa_entry.addr.in6 = laddrs->laddr.in6;
    }
    param->ifa_entry.flags |= IFA_F_SAPOOL;

    return;
}

int dpvs_add_laddr(dpvs_service_compat_t *svc, dpvs_laddr_table_t *laddr)
{
    struct inet_addr_param param;

    dpvs_ctrl_func = dpvs_add_laddr;

    dpvs_fill_laddr_conf(svc, laddr);

    dpvs_fill_ipaddr_conf(1, 0, laddr, &param);
    dpvs_setsockopt(SOCKOPT_SET_IFADDR_ADD, &param, sizeof(struct inet_addr_param));

    return dpvs_setsockopt(SOCKOPT_SET_LADDR_ADD, laddr, sizeof(dpvs_laddr_table_t));
}

int dpvs_del_laddr(dpvs_service_compat_t *svc, dpvs_laddr_table_t *laddr)
{
    struct inet_addr_param param;

    dpvs_ctrl_func = dpvs_del_laddr;

    dpvs_fill_laddr_conf(svc, laddr);

    dpvs_fill_ipaddr_conf(0, 0, laddr, &param);
    dpvs_setsockopt(SOCKOPT_SET_IFADDR_DEL, &param, sizeof(struct inet_addr_param));

    return dpvs_setsockopt(SOCKOPT_SET_LADDR_DEL, laddr, sizeof(dpvs_laddr_table_t));
}

/*for black list*/
static void dpvs_fill_blklst_conf(dpvs_service_compat_t *svc, dpvs_blklst_t *blklst)
{
    blklst->af    = svc->af;
    blklst->proto = svc->proto;
    blklst->vport = svc->port;
    blklst->vaddr = svc->addr;
}

int dpvs_add_blklst(dpvs_service_compat_t* svc, dpvs_blklst_t *blklst)
{
    dpvs_ctrl_func = dpvs_add_blklst;

    dpvs_fill_blklst_conf(svc, blklst);

    return dpvs_setsockopt(SOCKOPT_SET_BLKLST_ADD, blklst, sizeof(dpvs_blklst_t));
}

int dpvs_del_blklst(dpvs_service_compat_t* svc, dpvs_blklst_t *blklst)
{
    dpvs_ctrl_func = dpvs_del_blklst;

    dpvs_fill_blklst_conf(svc, blklst);

    return dpvs_setsockopt(SOCKOPT_SET_BLKLST_DEL, blklst, sizeof(dpvs_blklst_t));
}

/*for white list*/
static void dpvs_fill_whtlst_conf(dpvs_service_compat_t *svc, dpvs_whtlst_t *whtlst)
{
    whtlst->af        = svc->af;
    whtlst->proto     = svc->proto;
    whtlst->vport     = svc->port;
    whtlst->vaddr     = svc->addr;
}

int dpvs_add_whtlst(dpvs_service_compat_t* svc, dpvs_whtlst_t *whtlst)
{
    dpvs_ctrl_func = dpvs_add_whtlst;

    dpvs_fill_whtlst_conf(svc, whtlst);

    return dpvs_setsockopt(SOCKOPT_SET_WHTLST_ADD, whtlst, sizeof(dpvs_whtlst_t));
}

int dpvs_del_whtlst(dpvs_service_compat_t* svc, dpvs_whtlst_t *whtlst)
{
    dpvs_ctrl_func = dpvs_del_whtlst;

    dpvs_fill_whtlst_conf(svc, whtlst);

    return dpvs_setsockopt(SOCKOPT_SET_WHTLST_DEL, whtlst, sizeof(dpvs_whtlst_t));
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

int dpvs_add_tunnel(ipvs_tunnel_t *tunnel_entry)
{
    struct ip_tunnel_param conf;

    dpvs_ctrl_func = dpvs_add_tunnel;

    ipvs_fill_tunnel_conf(tunnel_entry, &conf);

    return dpvs_setsockopt(SOCKOPT_TUNNEL_ADD, &conf, sizeof(conf));
}

int dpvs_del_tunnel(ipvs_tunnel_t *tunnel_entry)
{
    struct ip_tunnel_param conf;

    dpvs_ctrl_func = dpvs_del_tunnel;

    ipvs_fill_tunnel_conf(tunnel_entry, &conf);

    return dpvs_setsockopt(SOCKOPT_TUNNEL_DEL, &conf, sizeof(conf));
}

int dpvs_set_timeout(ipvs_timeout_t *to)
{
    dpvs_ctrl_func = dpvs_set_timeout;

    return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_TIMEOUT, (char *)to,
            sizeof(*to));
}

int dpvs_start_daemon(ipvs_daemon_t *dm)
{
    dpvs_ctrl_func = dpvs_start_daemon;

    return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STARTDAEMON,
            (char *)&dm, sizeof(dm));
}


int dpvs_stop_daemon(ipvs_daemon_t *dm)
{
    dpvs_ctrl_func = dpvs_stop_daemon;

    return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STOPDAEMON,
            (char *)&dm, sizeof(dm));
}

dpvs_services_front_t* dpvs_get_services(dpvs_services_front_t* svcs) {
    dpvs_services_front_t* rcv;
    size_t lrcv, len;

    dpvs_ctrl_func = dpvs_get_services;

    assert(svcs);

    if (ESOCKOPT_OK != dpvs_getsockopt(DPVS_SO_GET_SERVICES, svcs,
                sizeof(dpvs_services_front_t), (void**)&rcv, &lrcv)) {
        return NULL;
    }

    len = svcs->count * sizeof(dpvs_service_compat_t) + sizeof(dpvs_services_front_t);

    memcpy(svcs, rcv, len < lrcv ? len : lrcv);

    dpvs_sockopt_msg_free(rcv);

    return svcs;
}

#ifdef _WITH_SNMP_CHECKER_
#endif	/* _WITH_SNMP_CHECKER_ */

dpvs_dest_table_t* dpvs_get_dests(dpvs_dest_table_t* table)
{
    size_t len, lrcv;
    dpvs_dest_table_t *rcv;
    assert(table);

    len = sizeof(dpvs_dest_table_t) + table->num_dests * sizeof(dpvs_dest_compat_t);

    if (ESOCKOPT_OK != dpvs_getsockopt(DPVS_SO_GET_DESTS, table,
                sizeof(dpvs_dest_table_t), (void**)&rcv, &lrcv)) {
        return NULL;
    }

    memcpy(table, rcv, len < lrcv ? len : lrcv);

    dpvs_sockopt_msg_free(rcv);

    return table;
}

dpvs_service_compat_t* dpvs_get_service(dpvs_service_compat_t* desc, dpvs_service_compat_t* detail)
{
    size_t len, lrcv;
    dpvs_service_compat_t *rcv;

    dpvs_ctrl_func = dpvs_get_service;

    assert(detail);

    len = sizeof(dpvs_service_compat_t);

    if (ESOCKOPT_OK != dpvs_getsockopt(DPVS_SO_GET_SERVICE, desc,
                len, (void**)&rcv, &lrcv)) {
        return NULL;
    }

    memcpy(detail, rcv, lrcv);
    dpvs_sockopt_msg_free(rcv);
    return detail;
}

int __attribute__ ((pure))
dpvs_cmp_services(dpvs_service_compat_t *s1, dpvs_service_compat_t *s2)
{
    int r, i;

    r = s1->fwmark - s2->fwmark;
    if (r != 0)
        return r;

    r = s1->af - s2->af;
    if (r != 0)
        return r;

    r = s1->proto - s2->proto;
    if (r != 0)
        return r;

    if (s1->af == AF_INET6)
        for (i = 0; !r && (i < 4); i++)
            r = ntohl(s1->addr.in6.s6_addr32[i]) - ntohl(s2->addr.in6.s6_addr32[i]);
    else
        r = ntohl(s1->addr.in.s_addr) - ntohl(s2->addr.in.s_addr);
    if (r != 0)
        return r;

    return ntohs(s1->port) - ntohs(s2->port);
}

int __attribute__ ((pure))
dpvs_cmp_dests(dpvs_dest_compat_t *d1, dpvs_dest_compat_t *d2)
{
    int r = 0, i;

    if (d1->af == AF_INET6)
        for (i = 0; !r && (i < 4); i++)
            r = ntohl(d1->addr.in6.s6_addr32[i]) -
                ntohl(d2->addr.in6.s6_addr32[i]);
    else
        r = ntohl(d1->addr.in.s_addr) - ntohl(d2->addr.in.s_addr);
    if (r != 0)
        return r;

    return ntohs(d1->port) - ntohs(d2->port);
}

void dpvs_sort_services(dpvs_services_front_t *s, dpvs_service_cmp_t f)
{
    qsort(s->entrytable, s->count,
            sizeof(dpvs_service_compat_t), (qsort_cmp_t)f);
}

void dpvs_sort_dests(dpvs_dest_table_t *d, dpvs_dest_cmp_t f)
{
    qsort(d->entrytable, d->num_dests,
            sizeof(dpvs_dest_compat_t), (qsort_cmp_t)f);
}

int dpvs_set_route(struct dp_vs_route_conf *rt, int cmd)
{
    int err = -1;

    dpvs_ctrl_func = dpvs_set_route;

    if (cmd == IPROUTE_DEL){
        err = dpvs_setsockopt(SOCKOPT_SET_ROUTE_DEL, rt, sizeof(struct dp_vs_route_conf));
    } else if (cmd == IPROUTE_ADD){
        err = dpvs_setsockopt(SOCKOPT_SET_ROUTE_ADD, rt, sizeof(struct dp_vs_route_conf));
    }

    return err;
}

int dpvs_set_route6(struct dp_vs_route6_conf *rt6_cfg, int cmd)
{
    int err = -1;

    dpvs_ctrl_func = dpvs_set_route6;

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

int dpvs_set_ipaddr(struct inet_addr_param *param, int cmd)
{
    int err = -1;

    dpvs_ctrl_func = dpvs_set_ipaddr;

    if (cmd == IPADDRESS_DEL)
        err = dpvs_setsockopt(SOCKOPT_SET_IFADDR_DEL, param, sizeof(struct inet_addr_param));
    else if (cmd == IPADDRESS_ADD)
        err = dpvs_setsockopt(SOCKOPT_SET_IFADDR_ADD, param, sizeof(struct inet_addr_param));

    return err;
}

int dpvs_send_gratuitous_arp(struct in_addr *in)
{
    dpvs_ctrl_func = dpvs_send_gratuitous_arp;

    return dpvs_setsockopt(DPVS_SO_SET_GRATARP, in, sizeof(in));
}

ipvs_timeout_t *dpvs_get_timeout(void)
{
#if 0
    ipvs_timeout_t *u;
    socklen_t len;

    dpvs_ctrl_func = dpvs_get_timeout;

    len = sizeof(*u);
    if (!(u = malloc(len)))
        return NULL;

    dpvs_ctrl_func = dpvs_get_timeout;
    if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_TIMEOUT,
                (char *)u, &len)) {
        free(u);
        return NULL;
    }
#endif
    return NULL;
}

ipvs_daemon_t *dpvs_get_daemon(void)
{
#if 0
    ipvs_daemon_t *u;
    socklen_t len;

    /* note that we need to get the info about two possible
       daemons, master and backup. */
    len = sizeof(*u) * 2;
    if (!(u = malloc(len)))
        return NULL;

    dpvs_ctrl_func = dpvs_get_daemon;
    if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_DAEMON, (char *)u, &len)) {
        free(u);
        return NULL;
    }
#endif

    return NULL;
}

void dpvs_ctrl_close(void)
{
    if (sockfd != -1) {
        close(sockfd);
        sockfd = -1;
    }
}

struct ip_vs_conn_array *dp_vs_get_conns(const struct ip_vs_conn_req *req)
{
    int res;
    size_t arrlen, rcvlen;
    struct ip_vs_conn_array *conn_arr, *arr_rcv;

    dpvs_ctrl_func = dp_vs_get_conns;

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

struct ip_vs_get_laddrs *dpvs_get_laddrs(dpvs_service_compat_t *svc, struct ip_vs_get_laddrs **laddrs)
{
    struct dp_vs_laddr_conf conf, *result;
    size_t res_size, len;
    int i;

    dpvs_ctrl_func = dpvs_get_laddrs;

    memset(&conf, 0, sizeof(struct dp_vs_laddr_conf));
    conf.af_s = svc->af;
    conf.proto = svc->proto;
    if (svc->af == AF_INET)
        conf.vaddr.in = svc->addr.in;
    else
        conf.vaddr.in6 = svc->addr.in6;
    conf.vport = svc->port;
    conf.fwmark = svc->fwmark;
    conf.cid = svc->cid;
    conf.index = svc->index;

    memcpy(&conf.match, &svc->match, sizeof(conf.match));

    if (ESOCKOPT_OK != dpvs_getsockopt(SOCKOPT_GET_LADDR_GETALL, &conf, sizeof(conf),
                (void **)&result, &res_size)) {
        return NULL;
    }

    len =  sizeof(struct ip_vs_get_laddrs) + result->nladdrs * sizeof(struct ip_vs_laddr_entry);
    *laddrs = malloc(len);

    if (*laddrs == NULL) {
        dpvs_sockopt_msg_free(result);
        return NULL;
    }

    memset(*laddrs, 0, len);
    (*laddrs)->protocol = result->proto;
    (*laddrs)->__addr_v4 = result->vaddr.in.s_addr;
    (*laddrs)->port = result->vport;
    (*laddrs)->fwmark = result->fwmark;
    (*laddrs)->num_laddrs = result->nladdrs;
    (*laddrs)->af = result->af_s;
    if (result->af_s == AF_INET)
        (*laddrs)->addr.in = result->vaddr.in;
    else
        (*laddrs)->addr.in6 = result->vaddr.in6;

    for (i = 0; i < result->nladdrs; i++) {
        (*laddrs)->entrytable[i].__addr_v4 = result->laddrs[i].addr.in.s_addr;
        (*laddrs)->entrytable[i].port_conflict = result->laddrs[i].nport_conflict;
        (*laddrs)->entrytable[i].conn_counts = result->laddrs[i].nconns;
        (*laddrs)->entrytable[i].af = result->laddrs[i].af;
        if (result->laddrs[i].af == AF_INET)
            (*laddrs)->entrytable[i].addr.in = result->laddrs[i].addr.in;
        else
            (*laddrs)->entrytable[i].addr.in6 = result->laddrs[i].addr.in6;
    }

    dpvs_sockopt_msg_free(result);
    return *laddrs;
}

struct dp_vs_blklst_conf_array *dpvs_get_blklsts(void)
{
    struct dp_vs_blklst_conf_array *array, *result;
    size_t size;
    int i;

    dpvs_ctrl_func = dpvs_get_blklsts;

    if (ESOCKOPT_OK != dpvs_getsockopt(SOCKOPT_GET_BLKLST_GETALL,
                NULL,
                0,
                (void **)&result,
                &size))
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

struct dp_vs_whtlst_conf_array *dpvs_get_whtlsts(void)
{
    struct dp_vs_whtlst_conf_array *array, *result;
    size_t size;
    int i;

    dpvs_ctrl_func = dpvs_get_whtlsts;

    if (ESOCKOPT_OK != dpvs_getsockopt(SOCKOPT_GET_WHTLST_GETALL,
                NULL,
                0,
                (void **)&result,
                &size)) {
        return NULL;
    }
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
        { dpvs_add_service, EEXIST, "Service already exists" },
        { dpvs_add_service, ENOENT, "Scheduler or persistence engine not found" },
        { dpvs_update_service, ESRCH, "No such service" },
        { dpvs_update_service, ENOENT, "Scheduler or persistence engine not found" },
        { dpvs_del_service, ESRCH, "No such service" },
        { dpvs_zero_service, ESRCH, "No such service" },
        { dpvs_add_dest, ESRCH, "Service not defined" },
        { dpvs_add_dest, EEXIST, "Destination already exists" },
        { dpvs_update_dest, ESRCH, "Service not defined" },
        { dpvs_update_dest, ENOENT, "No such destination" },
        { dpvs_del_dest, ESRCH, "Service not defined" },
        { dpvs_del_dest, ENOENT, "No such destination" },
        { dpvs_start_daemon, EEXIST, "Daemon has already run" },
        { dpvs_stop_daemon, ESRCH, "No daemon is running" },
        { dpvs_add_laddr, ESRCH, "Service not defined" },
        { dpvs_add_laddr, EEXIST, "Local address already exists" },
        { dpvs_del_laddr, ESRCH, "Service not defined" },
        { dpvs_del_laddr, ENOENT, "No such Local address" },
        { dpvs_get_laddrs, ESRCH, "Service not defined" },
        { dpvs_add_blklst, ESRCH, "Service not defined" },
        { dpvs_add_blklst, EEXIST, "blacklist address already exists" },
        { dpvs_del_blklst, ESRCH, "Service not defined" },
        { dpvs_del_blklst, ENOENT, "No such deny address" },
        { dpvs_add_whtlst, ESRCH, "Service not defined" },
        { dpvs_add_whtlst, EEXIST, "whitelist address already exists" },
        { dpvs_del_whtlst, ESRCH, "Service not defined" },
        { dpvs_del_whtlst, ENOENT, "No such deny address" },
        { dpvs_get_blklsts, ESRCH, "Service not defined" },
        { dpvs_get_whtlsts, ESRCH, "Service not defined" },
        { dpvs_get_dests, ESRCH, "No such service" },
        { 0, EPERM, "Permission denied (you must be root)" },
        { 0, EINVAL, "Invalid operation.  Possibly wrong module version, address not unicast, ..." },
        { 0, ENOPROTOOPT, "Protocol not available" },
        { 0, ENOMEM, "Memory allocation problem" },
        { 0, EOPNOTSUPP, "Operation not supported with IPv6" },
        { 0, EAFNOSUPPORT, "Operation not supported with specified address family" },
        { 0, EMSGSIZE, "Module is wrong version" },
    };

    for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
        if ((!table[i].func || table[i].func == dpvs_ctrl_func)
                && table[i].err == err)
            return table[i].message;
    }

    return strerror(err);
}

