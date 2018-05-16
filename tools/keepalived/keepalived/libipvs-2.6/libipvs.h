/*
 * libipvs.h:	header file for the library ipvs
 *
 * Version:	$Id: libipvs.h,v 1.7 2003/06/08 09:31:39 wensong Exp $
 *
 * Authors:	Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 */

#ifndef _LIBIPVS_H
#define _LIBIPVS_H

#include "ip_vs.h"

#define OPT_NONE		0x000000
#define OPT_NUMERIC		0x000001
#define OPT_CONNECTION		0x000002
#define OPT_SERVICE		0x000004
#define OPT_SCHEDULER		0x000008
#define OPT_PERSISTENT		0x000010
#define OPT_NETMASK		0x000020
#define OPT_SERVER		0x000040
#define OPT_FORWARD		0x000080
#define OPT_WEIGHT		0x000100
#define OPT_UTHRESHOLD		0x000200
#define OPT_LTHRESHOLD		0x000400
#define OPT_MCAST		0x000800
#define OPT_TIMEOUT		0x001000
#define OPT_DAEMON		0x002000
#define OPT_STATS		0x004000
#define OPT_RATE		0x008000
#define OPT_THRESHOLDS		0x010000
#define OPT_PERSISTENTCONN	0x020000
#define OPT_NOSORT		0x040000
#define OPT_SYNCID		0x080000
#define OPT_EXACT		0x100000
#define OPT_ONEPACKET		0x200000
#define OPT_PERSISTENCE_ENGINE	0x400000
#define OPT_LOCAL_ADDRESS	0x800000
#define OPT_BLKLST_ADDRESS	0x1000000
#define OPT_SYNPROXY		0x2000000
#define OPT_IFNAME		0x4000000
#define OPT_SOCKPAIR		0x8000000
#define OPT_SIPHASH		0x10000000
#define OPT_QIDHASH		0x20000000
#define OPT_HASHTAG		0x40000000
#define NUMBER_OF_OPT		31

#define MINIMUM_IPVS_VERSION_MAJOR      1
#define MINIMUM_IPVS_VERSION_MINOR      1
#define MINIMUM_IPVS_VERSION_PATCH      4

#ifndef IPVS_VERSION
#define IPVS_VERSION(x,y,z)		(((x)<<16)+((y)<<8)+(z))
#endif

/*
 * The default IPVS_SVC_PERSISTENT_TIMEOUT is a little larger than average
 * connection time plus IPVS TCP FIN timeout (2*60 seconds). Because the
 * connection template won't be released until its controlled connection
 * entries are expired.
 * If IPVS_SVC_PERSISTENT_TIMEOUT is too less, the template will expire
 * soon and will be put in expire again and again, which causes additional
 * overhead. If it is too large, the same will always visit the same
 * server, which may make dynamic load imbalance worse.
 */
#define IPVS_SVC_PERSISTENT_TIMEOUT	(6*60)


typedef struct ip_vs_service_user	ipvs_service_t;
typedef struct ip_vs_dest_user		ipvs_dest_t;
typedef struct ip_vs_laddr_user 	ipvs_laddr_t;
typedef struct ip_vs_blklst_user        ipvs_blklst_t;
typedef struct ip_vs_timeout_user	ipvs_timeout_t;
typedef struct ip_vs_daemon_user	ipvs_daemon_t;
typedef struct ip_vs_service_entry	ipvs_service_entry_t;
typedef struct ip_vs_dest_entry		ipvs_dest_entry_t;
typedef struct ip_vs_laddr_entry	ipvs_laddr_entry_t;
typedef struct ip_vs_blklst_entry       ipvs_blklst_entry_t;

/* ipvs info variable */
extern struct ip_vs_getinfo ipvs_info;

/* init socket and get ipvs info */
extern int ipvs_init(void);

/* get ipvs info separately */
extern int ipvs_getinfo(void);

/* get the version number */
extern unsigned int ipvs_version(void);

/* flush all the rules */
extern int ipvs_flush(void);

/* add a virtual service */
extern int ipvs_add_service(ipvs_service_t *svc);

/* update a virtual service with new options */
extern int ipvs_update_service(ipvs_service_t *svc);

/* update a virtual service based on option */
extern int ipvs_update_service_by_options(ipvs_service_t *svc, unsigned int options);

/* config the service's synproxy switch */
extern int ipvs_update_service_synproxy(ipvs_service_t *svc , int enable);

/* delete a virtual service */
extern int ipvs_del_service(ipvs_service_t *svc);

/* zero the counters of a service or all */
extern int ipvs_zero_service(ipvs_service_t *svc);

/* add a destination server into a service */
extern int ipvs_add_dest(ipvs_service_t *svc, ipvs_dest_t *dest);

/* update a destination server with new options */
extern int ipvs_update_dest(ipvs_service_t *svc, ipvs_dest_t *dest);

/* remove a destination server from a service */
extern int ipvs_del_dest(ipvs_service_t *svc, ipvs_dest_t *dest);

extern struct ip_vs_conn_array* ip_vs_get_conns(const struct ip_vs_conn_req *req);

extern int ipvs_add_laddr(ipvs_service_t *svc, ipvs_laddr_t * laddr);
extern int ipvs_del_laddr(ipvs_service_t *svc, ipvs_laddr_t * laddr);
extern struct ip_vs_get_laddrs *ipvs_get_laddrs(ipvs_service_entry_t *svc);

/*for add/delete a blacklist ip*/
extern int ipvs_add_blklst(ipvs_service_t *svc, ipvs_blklst_t * blklst);
extern int ipvs_del_blklst(ipvs_service_t *svc, ipvs_blklst_t * blklst);

/* set timeout */
extern int ipvs_set_timeout(ipvs_timeout_t *to);

/* start a connection synchronizaiton daemon (master/backup) */
extern int ipvs_start_daemon(ipvs_daemon_t *dm);

/* stop a connection synchronizaiton daemon (master/backup) */
extern int ipvs_stop_daemon(ipvs_daemon_t *dm);


/* get all the ipvs services */
extern struct ip_vs_get_services *ipvs_get_services(void);

/* sort the service entries */
typedef int (*ipvs_service_cmp_t)(ipvs_service_entry_t *,
				  ipvs_service_entry_t *);
extern int ipvs_cmp_services(ipvs_service_entry_t *s1,
			     ipvs_service_entry_t *s2);
extern void ipvs_sort_services(struct ip_vs_get_services *s,
			       ipvs_service_cmp_t f);

/* get the destination array of the specified service */
extern struct ip_vs_get_dests *ipvs_get_dests(ipvs_service_entry_t *svc);

/* sort the destination entries */
typedef int (*ipvs_dest_cmp_t)(ipvs_dest_entry_t *,
			       ipvs_dest_entry_t *);
extern int ipvs_cmp_dests(ipvs_dest_entry_t *d1,
			  ipvs_dest_entry_t *d2);
extern void ipvs_sort_dests(struct ip_vs_get_dests *d,
			    ipvs_dest_cmp_t f);

/* get an ipvs service entry */
extern ipvs_service_entry_t *ipvs_get_service(struct ip_vs_service_user *hint);

/* get ipvs timeout */
extern ipvs_timeout_t *ipvs_get_timeout(void);

/* get ipvs daemon information */
extern ipvs_daemon_t *ipvs_get_daemon(void);

/* close the socket */
extern void ipvs_close(void);

extern const char *ipvs_strerror(int err);

extern int ipvs_send_gratuitous_arp(struct in_addr *in);

extern int ipvs_set_route(struct dp_vs_route_conf*, int cmd);

extern int ipvs_set_ipaddr(struct inet_addr_param *param, int cmd);

extern struct dp_vs_blklst_conf_array *ipvs_get_blklsts(void);

#endif /* _LIBIPVS_H */
