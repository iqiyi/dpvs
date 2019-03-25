/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <string.h>
#include <assert.h>
#include "ipset.h"
#include "conf/ipset.h"
#include "ctrl.h"

#define IPSET_TAB_SIZE (1<<8)
#define IPSET_TAB_MASK (IPSET_TAB_SIZE - 1)

#define this_ipset_lcore        (RTE_PER_LCORE(ipset_lcore))
#define this_ipset_table_lcore  (this_ipset_lcore.ipset_table)
#define this_num_ipset          (RTE_PER_LCORE(num_ipset))

#define MSG_TYPE_IPSET_ADD                  19
#define MSG_TYPE_IPSET_DEL                  20
#define MSG_TYPE_IPSET_FLUSH                21


struct ipset_lcore{
	struct list_head ipset_table[IPSET_TAB_SIZE];
};

static RTE_DEFINE_PER_LCORE(struct ipset_lcore, ipset_lcore);
static RTE_DEFINE_PER_LCORE(rte_atomic32_t, num_ipset);


struct ipset_addr {
	int af;
	union inet_addr    addr;
};

struct ipset_entry {
    struct list_head list;
    struct ipset_addr daddr;
	int route_table_num;
};

static inline unsigned int ipset_addr_hash(int af, union inet_addr *addr)
{
    uint32_t addr_fold;

    addr_fold = inet_addr_fold(af, addr);

    if (!addr_fold) {
        RTE_LOG(DEBUG, IPSET, "%s: IP proto not support.\n", __func__);
        return 0;
    }

    return rte_be_to_cpu_32(addr_fold)&IPSET_TAB_MASK;
}


static struct ipset_entry *ipset_new_entry(int af, union inet_addr * dest)
{
    struct ipset_entry *new_ipset=NULL;
    if(!dest)
        return NULL;
    new_ipset = rte_zmalloc("new_ipset_entry", sizeof(struct ipset_entry), 0);
    if (new_ipset == NULL){
        return NULL;
    }
	new_ipset->daddr.af = af;
	memcpy(&new_ipset->daddr.addr, dest, sizeof(union inet_addr));
    new_ipset->route_table_num = 0;
    return new_ipset;
}


int ipset_add(int af, union inet_addr *dest)
{
    unsigned int hashkey;
    struct ipset_entry *ipset_node, *ipset_new;

    hashkey = ipset_addr_hash(af, dest);

    list_for_each_entry(ipset_node, &this_ipset_table_lcore[hashkey], list){
        if (ipset_node->daddr.af == af && inet_addr_equal(af, &ipset_node->daddr.addr, dest)) {
            return EDPVS_EXIST;
        }
    }

    ipset_new = ipset_new_entry(af, dest);
    if (!ipset_new){
        return EDPVS_NOMEM;
    }
 
    list_add(&ipset_new->list, &this_ipset_table_lcore[hashkey]);
	rte_atomic32_inc(&this_num_ipset);	
    return EDPVS_OK;
}

struct ipset_entry *ipset_addr_lookup(int af, union inet_addr *dest)
{
    unsigned int hashkey;
    struct ipset_entry *ipset_node;

    hashkey = ipset_addr_hash(af, dest);
    list_for_each_entry(ipset_node, &this_ipset_table_lcore[hashkey], list){
        if (ipset_node->daddr.af == af && inet_addr_equal(af, &ipset_node->daddr.addr, dest)) {
            return ipset_node;
        }
    }
    return NULL;
}


int ipset_del(int af, union inet_addr *dest)
{
	struct ipset_entry *ipset_node;

	ipset_node = ipset_addr_lookup(af, dest);
	if (!ipset_node)
		return EDPVS_NOTEXIST;
	list_del(&ipset_node->list);
        rte_free(ipset_node);
        rte_atomic32_dec(&this_num_ipset);
        return EDPVS_OK; 
}

#ifdef CONFIG_DPVS_IPSET_DEBUG
int ipset_list(void)
{
	struct ipset_entry *ipset_node;
	int i;
	char ip6str[64], ip4str[32];
	for (i = 0; i < IPSET_TAB_SIZE; i++) {
		list_for_each_entry(ipset_node, &this_ipset_table_lcore[i], list){
			if (ipset_node && ipset_node->daddr.af == AF_INET) {
                                inet_ntop(AF_INET, (union inet_addr*)&ipset_node->daddr.addr, ip4str, sizeof(ip4str));
                                printf("%s\n", ip4str);
			}
			else if (ipset_node && ipset_node->daddr.af == AF_INET6) {
				inet_ntop(AF_INET6, (union inet_addr*)&ipset_node->daddr.addr, ip6str, sizeof(ip6str));
				printf("%s\n", ip6str);
			}	
		}		
	}
    return 0;
}

int ipset_test(void)
{
	ulong ip4;
	char *ip6;
	struct in_addr ipv4;
	struct in6_addr ipv6;
	ip4 = inet_addr("192.168.168.168");
	ip6 = strdup("2a01:198:603:0:396e:4789:8e99:890f");
	memcpy(&ipv4, &ip4, sizeof(ip4));
	inet_pton(AF_INET6, ip6, &ipv6);
	ipset_add(AF_INET, (union inet_addr *)&ipv4);
	ipset_list();
	printf("%d\n", this_num_ipset.cnt);
	ipset_add(AF_INET6, (union inet_addr *)&ipv6);
	ipset_list();	
	printf("%d\n", this_num_ipset.cnt);
	ipset_del(AF_INET, (union inet_addr *)&ipv4);
	ipset_list();	
	printf("%d\n", this_num_ipset.cnt);
        ip4 = inet_addr("192.168.168.166");
        memcpy(&ipv4, &ip4, sizeof(ip4));
	ipset_del(AF_INET, (union inet_addr *)&ipv4);
	ipset_list();	
	printf("%d\n", this_num_ipset.cnt);
	ipset_del(AF_INET6, (union inet_addr *)&ipv6);
	ipset_list();	
	printf("%d\n", this_num_ipset.cnt);
        ip4 = inet_addr("192.168.14.57");
        memcpy(&ipv4, &ip4, sizeof(ip4));
	ipset_add(AF_INET, (union inet_addr *)&ipv4);
	ipset_list();	

	return this_num_ipset.cnt;
}
#endif

static int ipset_add_del(bool add, int af, union inet_addr *dest)
{
	lcoreid_t cid = rte_lcore_id();
	struct dpvs_msg *msg;
    struct dp_vs_ipset_conf cf;
	int err = 0;

	if (add)
		err = ipset_add(af, dest);
	else
		err = ipset_del(af, dest);
	if (err != EDPVS_OK) {
		return err;
	}

	memset(&cf, 0, sizeof(struct dp_vs_ipset_conf));
	cf.af = af;
	memcpy(&cf.addr, dest, sizeof(union inet_addr));

	if (add)
        msg = msg_make(MSG_TYPE_IPSET_ADD, 0, DPVS_MSG_MULTICAST,
                       cid, sizeof(struct dp_vs_ipset_conf), &cf);
    else
        msg = msg_make(MSG_TYPE_IPSET_DEL, 0, DPVS_MSG_MULTICAST,
                       cid, sizeof(struct dp_vs_ipset_conf), &cf);

    err = multicast_msg_send(msg, 0/*DPVS_MSG_F_ASYNC*/, NULL);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        return err;
    }
    msg_destroy(&msg);

    return EDPVS_OK;
}

static int ipset_flush_lcore(void *arg)
{
	struct ipset_entry *ipset_node, *next;
	int i;
        
        if (!rte_lcore_is_enabled(rte_lcore_id()))
            return EDPVS_DISABLED;

	for (i = 0; i < IPSET_TAB_SIZE; i++) {
	    list_for_each_entry_safe(ipset_node, next, &this_ipset_table_lcore[i], list){
                if (ipset_node) {
		    list_del(&ipset_node->list);
		    rte_free(ipset_node);
    		    rte_atomic32_dec(&this_num_ipset);
                }
            }
        }
    return 0;
}

static int ipset_flush(void)
{
	lcoreid_t cid = rte_lcore_id();
	struct dpvs_msg *msg;	
	int err = 0;

	ipset_flush_lcore(NULL);
	msg = msg_make(MSG_TYPE_IPSET_FLUSH, 0, DPVS_MSG_MULTICAST,
						   cid, 0, NULL);
	
	err = multicast_msg_send(msg, 0/*DPVS_MSG_F_ASYNC*/, NULL);
	if (err != EDPVS_OK) {
		msg_destroy(&msg);
		return err;
	}
	msg_destroy(&msg);

	return EDPVS_OK;
}

static int ipset_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    struct dp_vs_multi_ipset_conf *cf = (void *)conf;
    struct dp_vs_ipset_conf *ip_cf = NULL;
    int i, err;

    if (opt == SOCKOPT_SET_IPSET_FLUSH)
        return ipset_flush();
	
    if (!conf || size < sizeof(*cf))
        return EDPVS_INVAL;

    for (i = 0; i < cf->num; i++) {
        ip_cf = &cf->ipset_conf[i];
        if (ip_cf == NULL)
            return EDPVS_NOTSUPP;
        if (ip_cf->af != AF_INET && ip_cf->af != AF_INET6)
            return EDPVS_NOTSUPP;	
        switch (opt) {
    	    case SOCKOPT_SET_IPSET_ADD:
                 err = ipset_add_del(true, ip_cf->af, &ip_cf->addr);
	         if (err != EDPVS_OK)
	             return err;
	          continue;
            case SOCKOPT_SET_IPSET_DEL:
                 err = ipset_add_del(false, ip_cf->af, &ip_cf->addr);
                 if (err != EDPVS_OK)
	             return err;
	         continue;
            default:
    	         return EDPVS_NOTSUPP;		
	}
    } 
    return EDPVS_OK;
}

static int ipset_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    size_t nips;
	struct ipset_entry *ipset_node;
    struct dp_vs_ipset_conf_array *array;
	int i;
	int off = 0;
	
	nips = rte_atomic32_read(&this_num_ipset);
	*outsize = sizeof(struct dp_vs_ipset_conf_array) + \
               nips * sizeof(struct dp_vs_ipset_conf);
    *out = rte_calloc_socket(NULL, 1, *outsize, 0, rte_socket_id());
    if (!(*out))
        return EDPVS_NOMEM;
	array = *out;

	for (i = 0; i < IPSET_TAB_SIZE; i++) {
            list_for_each_entry(ipset_node, &this_ipset_table_lcore[i], list) {
                if (off >= nips)
                    break;
				memcpy(&array->ips[off].addr.in, &ipset_node->daddr.addr, sizeof(union inet_addr));
                array->ips[off++].af = ipset_node->daddr.af;
            }
        }
	array->nipset = off;
	
	return 0;
}

 static int ipset_msg_process(bool add, struct dpvs_msg *msg)
 {
	 struct dp_vs_ipset_conf *cf;
	 int err;
 
	 assert(msg);
	 if (msg->len != sizeof(struct dp_vs_ipset_conf)) {
		 return EDPVS_INVAL;
	 }
 
	 /* set route config */
	 cf = (struct dp_vs_ipset_conf *)msg->data;
	 if (add)
		 err = ipset_add(cf->af, &cf->addr);
	 else
 		 err = ipset_del(cf->af, &cf->addr);
	 
	 if (err != EDPVS_OK)
         RTE_LOG(ERR, IPSET, "%s: fail to %s ipset.\n", __func__, add? "add":"del");
	 return err;
 }


static int ipset_add_msg_cb(struct dpvs_msg *msg)
{
    return ipset_msg_process(true, msg);
}

static int ipset_del_msg_cb(struct dpvs_msg *msg)
{
    return ipset_msg_process(false, msg);
}		

static int ipset_flush_msg_cb(struct dpvs_msg *msg)
{
    return ipset_flush_lcore(NULL);
}

static int ipset_lcore_init(void *arg)
{
    int i;

    if (!rte_lcore_is_enabled(rte_lcore_id()))
        return EDPVS_DISABLED;

    for (i = 0; i < IPSET_TAB_SIZE; i++)
        INIT_LIST_HEAD(&this_ipset_table_lcore[i]);

    return EDPVS_OK;
}


static struct dpvs_sockopts ipset_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_IPSET_ADD,
    .set_opt_max    = SOCKOPT_SET_IPSET_FLUSH,
    .set            = ipset_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_IPSET_SHOW,
    .get_opt_max    = SOCKOPT_GET_IPSET_SHOW,
    .get            = ipset_sockopt_get,
};

int ipset_term(void)
{
    int err;
    lcoreid_t cid;

    if ((err = sockopt_unregister(&ipset_sockopts)) != EDPVS_OK)
        return err;

    rte_eal_mp_remote_launch(ipset_flush_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, IPSET, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
        }
    }

    return EDPVS_OK;
}

int ipset_init(void)
{
    int err;
    lcoreid_t cid;
    struct dpvs_msg_type msg_type;

    rte_atomic32_set(&this_num_ipset, 0);    

    /* master core also need routes */
    rte_eal_mp_remote_launch(ipset_lcore_init, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, IPSET, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
            return err;
        }
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_IPSET_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = ipset_add_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPSET, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_IPSET_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = ipset_del_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPSET, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_IPSET_FLUSH;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = ipset_flush_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPSET, "%s: fail to register msg.\n", __func__);
        return err;
    }

    if ((err = sockopt_register(&ipset_sockopts)) != EDPVS_OK)
        return err;

    return EDPVS_OK;
}



