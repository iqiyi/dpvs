/*
 * libipvs.h:	header file for the library ipvs
 *
 * Authors:	Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 */

#ifndef _LIBIPVS_H
#define _LIBIPVS_H

//#include "config.h"
#include "ip_vs.h"

#define OPT_NONE                     0x000000
#define OPT_NUMERIC                  0x000001
#define OPT_CONNECTION               0x000002
#define OPT_SERVICE                  0x000004
#define OPT_SCHEDULER                0x000008
#define OPT_PERSISTENT               0x000010
#define OPT_NETMASK                  0x000020
#define OPT_SERVER                   0x000040
#define OPT_FORWARD                  0x000080
#define OPT_WEIGHT                   0x000100
#define OPT_UTHRESHOLD               0x000200
#define OPT_LTHRESHOLD               0x000400
#define OPT_MCAST                    0x000800
#define OPT_TIMEOUT                  0x001000
#define OPT_DAEMON                   0x002000
#define OPT_STATS                    0x004000
#define OPT_RATE                     0x008000
#define OPT_THRESHOLDS               0x010000
#define OPT_PERSISTENTCONN           0x020000
#define OPT_NOSORT                   0x040000
#define OPT_SYNCID                   0x080000
#define OPT_EXACT                    0x100000
#define OPT_ONEPACKET                0x200000
#define OPT_PERSISTENCE_ENGINE       0x400000
#define OPT_LOCAL_ADDRESS            0x800000
#define OPT_BLKLST_ADDRESS          0x1000000
#define OPT_SYNPROXY                0x2000000
#define OPT_IFNAME                  0x4000000
#define OPT_SOCKPAIR                0x8000000
#define OPT_HASHTAG                0x10000000
#define OPT_CPU                    0x20000000
#define OPT_EXPIRE_QUIESCENT_CONN  0x40000000
#define OPT_WHTLST_ADDRESS         0x80000000
#define NUMBER_OF_OPT                   33

#define MINIMUM_IPVS_VERSION_MAJOR      1
#define MINIMUM_IPVS_VERSION_MINOR      1
#define MINIMUM_IPVS_VERSION_PATCH      4


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

extern struct ip_vs_getinfo g_ipvs_info;

typedef struct ip_vs_service_app	ipvs_service_t;
typedef struct ip_vs_dest_app		ipvs_dest_t;
typedef struct ip_vs_timeout_user	ipvs_timeout_t;
typedef struct ip_vs_daemon_app		ipvs_daemon_t;
typedef struct ip_vs_service_entry_app	ipvs_service_entry_t;
typedef struct ip_vs_dest_entry_app	ipvs_dest_entry_t;
typedef struct ip_vs_laddr_user 	ipvs_laddr_t;
typedef struct ip_vs_blklst_user	ipvs_blklst_t;
typedef struct ip_vs_whtlst_user	ipvs_whtlst_t;
typedef struct ip_vs_tunnel_user	ipvs_tunnel_t;
typedef struct ip_vs_laddr_entry	ipvs_laddr_entry_t;
typedef struct ip_vs_blklst_entry	ipvs_blklst_entry_t;
typedef struct ip_vs_whtlst_entry	ipvs_whtlst_entry_t;
typedef struct ip_vs_stats_user	ip_vs_stats_t;


/* init socket and get ipvs info */
extern int dpvs_ctrl_init(lcoreid_t cid);
/* close the socket */
extern void dpvs_ctrl_close(void);

/* Set timeout parameters */
extern int dpvs_set_timeout(ipvs_timeout_t *to);

/* flush all the rules */
extern int dpvs_flush(void);

/* add a virtual service */
extern int dpvs_add_service(dpvs_service_compat_t *svc);

/* update a virtual service with new options */
extern int dpvs_update_service(dpvs_service_compat_t *svc);

/* update a virtual service based on option */
extern int dpvs_update_service_by_options(dpvs_service_compat_t *svc, unsigned int options);

/* delete a virtual service */
extern int dpvs_del_service(dpvs_service_compat_t *svc);
/* zero the counters of a service or all */
extern int dpvs_zero_service(dpvs_service_compat_t *svc);

/* add a destination server into a service */
extern int dpvs_add_dest(dpvs_service_compat_t *svc, dpvs_dest_compat_t *dest);
/* update a destination server with new options */
extern int dpvs_update_dest(dpvs_service_compat_t *svc, dpvs_dest_compat_t *dest);
/* remove a destination server from a service */
extern int dpvs_del_dest(dpvs_service_compat_t *svc, dpvs_dest_compat_t *dest);

extern struct ip_vs_conn_array *dp_vs_get_conns(const struct ip_vs_conn_req *req);
extern struct ip_vs_get_laddrs *dpvs_get_laddrs(dpvs_service_compat_t *svc, struct ip_vs_get_laddrs **laddrs);
extern int dpvs_add_laddr(dpvs_service_compat_t *svc, dpvs_laddr_table_t *laddr);
extern int dpvs_del_laddr(dpvs_service_compat_t *svc, dpvs_laddr_table_t *laddr);

/*for add/delete a blacklist ip*/
extern int dpvs_add_blklst(dpvs_service_compat_t* svc, dpvs_blklst_t *blklst);
extern int dpvs_del_blklst(dpvs_service_compat_t* svc, dpvs_blklst_t *blklst);

/*for add/delete a whitelist ip*/
extern int dpvs_add_whtlst(dpvs_service_compat_t*,dpvs_whtlst_t *whtlst);
extern int dpvs_del_whtlst(dpvs_service_compat_t*,dpvs_whtlst_t *whtlst);

/*for add/delete a tunnel*/
extern int dpvs_add_tunnel(ipvs_tunnel_t * tunnel_entry);
extern int dpvs_del_tunnel(ipvs_tunnel_t * tunnel_entry);

/* start a connection synchronizaiton daemon (master/backup) */
extern int dpvs_start_daemon(ipvs_daemon_t *dm);

/* stop a connection synchronizaiton daemon (master/backup) */
extern int dpvs_stop_daemon(ipvs_daemon_t *dm);

/* get all the ipvs services */
extern dpvs_services_front_t *dpvs_get_services(dpvs_services_front_t *t);

/* get the destination array of the specified service */
extern dpvs_dest_table_t* dpvs_get_dests(dpvs_dest_table_t* table);

/* get an ipvs service entry */
extern dpvs_service_compat_t *dpvs_get_service(dpvs_service_compat_t*, dpvs_service_compat_t*);

/* get ipvs timeout */
extern ipvs_timeout_t *dpvs_get_timeout(void);

/* get ipvs daemon information */
extern ipvs_daemon_t *dpvs_get_daemon(void);

extern const char *ipvs_strerror(int err);

extern int dpvs_send_gratuitous_arp(struct in_addr *in);

extern int dpvs_set_route(struct dp_vs_route_conf*, int cmd);

extern int dpvs_set_route6(struct dp_vs_route6_conf*, int cmd);

extern int dpvs_set_ipaddr(struct inet_addr_param *param, int cmd);

extern struct dp_vs_blklst_conf_array *dpvs_get_blklsts(void);

typedef int (*dpvs_service_cmp_t)(dpvs_service_compat_t *,dpvs_service_compat_t*);
extern void dpvs_sort_services(dpvs_services_front_t *s, dpvs_service_cmp_t f);
extern int dpvs_cmp_services(dpvs_service_compat_t *s1, dpvs_service_compat_t *s2);

typedef int (*dpvs_dest_cmp_t)(dpvs_dest_compat_t*, dpvs_dest_compat_t*);
extern void dpvs_sort_dests(dpvs_dest_table_t *d, dpvs_dest_cmp_t f);
extern int dpvs_cmp_dests(dpvs_dest_compat_t *d1, dpvs_dest_compat_t  *d2);

extern struct dp_vs_whtlst_conf_array *dpvs_get_whtlsts(void);

#endif /* _LIBIPVS_H */
