/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
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
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <glob.h>
#include "ipset.h"
#include "conf/ipset.h"
#include "ctrl.h"
#include "conf/common.h"
#include "parser/parser.h"

#define IPSET_TAB_SIZE (1<<8)
#define IPSET_TAB_MASK (IPSET_TAB_SIZE - 1)

#define this_ipset_lcore        (RTE_PER_LCORE(ipset_lcore))
#define this_ipset_table_lcore  (this_ipset_lcore.ipset_table)
#define this_num_ipset          (RTE_PER_LCORE(num_ipset))

struct ipset_lcore{
	struct list_head ipset_table[IPSET_TAB_SIZE];
};

static RTE_DEFINE_PER_LCORE(struct ipset_lcore, ipset_lcore);
static RTE_DEFINE_PER_LCORE(uint32_t, num_ipset);

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


static struct ipset_entry *ipset_new_entry(int af, union inet_addr *dest)
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
    this_num_ipset++;	
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
    this_num_ipset--;
    return EDPVS_OK; 
}

static int ipset_add_del(bool add, struct dp_vs_multi_ipset_conf *cf)
{
	lcoreid_t cid = rte_lcore_id();
	struct dpvs_msg *msg;
        struct dp_vs_ipset_conf *ip_cf;
	int err = 0;
	int i, multi_ipset_msg_size;

    for (i = 0; i < cf->num; i++) {
        ip_cf = &cf->ipset_conf[i];
        if (ip_cf->af != AF_INET && ip_cf->af != AF_INET6)              
            continue;
        if (add)
            err = ipset_add(ip_cf->af, &ip_cf->addr);
        else
            err = ipset_del(ip_cf->af, &ip_cf->addr); 
    }
    
    if (err != EDPVS_OK) {
        return err;
    }

    multi_ipset_msg_size = sizeof(struct dp_vs_multi_ipset_conf) 
                                + cf->num*sizeof(struct dp_vs_ipset_conf);
    if (add)
        msg = msg_make(MSG_TYPE_IPSET_ADD, 0, DPVS_MSG_MULTICAST,
                           cid, multi_ipset_msg_size, cf);
    else
        msg = msg_make(MSG_TYPE_IPSET_DEL, 0, DPVS_MSG_MULTICAST,
                           cid, multi_ipset_msg_size, cf);

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
                this_num_ipset--;
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
    int err;

    if (opt == SOCKOPT_SET_IPSET_FLUSH)
        return ipset_flush();
	
    if (!conf || size < sizeof(struct dp_vs_multi_ipset_conf) + sizeof(struct dp_vs_ipset_conf))
        return EDPVS_INVAL;
	
    switch (opt) {
        case SOCKOPT_SET_IPSET_ADD:
            err = ipset_add_del(true, cf);
            break;
        case SOCKOPT_SET_IPSET_DEL:
            err = ipset_add_del(false, cf);
            break;
        default:
            return EDPVS_NOTSUPP;		
    }

    return err;
}

static int ipset_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    size_t nips;
    struct ipset_entry *ipset_node;
    struct dp_vs_ipset_conf_array *array;
    int i;
    int off = 0;
	
    nips = this_num_ipset;
    *outsize = sizeof(struct dp_vs_ipset_conf_array) + \
                   nips * sizeof(struct dp_vs_ipset_conf);
    *out = rte_calloc(NULL, 1, *outsize, 0);
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
    struct dp_vs_multi_ipset_conf *cf;
    struct dp_vs_ipset_conf *ip_cf;
    int err = 0;
    int i;
 
    assert(msg);
 
    if (msg->len < sizeof(struct dp_vs_multi_ipset_conf) + sizeof(struct dp_vs_ipset_conf)) {
        return EDPVS_INVAL;
    }
    
    cf = (struct dp_vs_multi_ipset_conf *)msg->data;

    for (i = 0; i < cf->num; i++) {
        ip_cf = &cf->ipset_conf[i];
        if (add)
            err = ipset_add(ip_cf->af, &ip_cf->addr);
        else
            err = ipset_del(ip_cf->af, &ip_cf->addr); 
    }
	 
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

    if (!netif_lcore_is_fwd_worker(rte_lcore_id()))
        return EDPVS_NOTSUPP;

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

static int ipset_parse_conf_file(void)
{
    char *buf, ch;
    struct dp_vs_multi_ipset_conf *ips = NULL;
    int ip_num = 0, ipset_size = 0, ip_index = 0;

    buf = (char *) MALLOC(CFG_FILE_MAX_BUF_SZ);
    if (buf == NULL) {
        RTE_LOG(WARNING, IPSET, "no memory for ipset buf\n");
        return -1;
    }
    while (!feof(g_current_stream)) {
        if ((ch=getc(g_current_stream)) == '\n')
            ip_num++;
    }
    if (!ip_num) {
        RTE_LOG(WARNING, IPSET, "no ip in the gfwip \n");
        FREE(buf);
        return -1;
    }
        
    RTE_LOG(DEBUG, IPSET, "gfwip list has %u ips\n", ip_num);

    fseek(g_current_stream, 0, SEEK_SET);

    ipset_size = sizeof(struct dp_vs_multi_ipset_conf) + ip_num*sizeof(struct dp_vs_ipset_conf);
    ips = rte_calloc(NULL, 1, ipset_size, 0);
    if (ips == NULL) {
        RTE_LOG(WARNING, IPSET, "no memory for ipset conf\n");
        FREE(buf);
        return -1;
    }                        
    ips->num = ip_num;

    while (read_line(buf, CFG_FILE_MAX_BUF_SZ)) {
        if (inet_pton(AF_INET, buf, &ips->ipset_conf[ip_index].addr) <= 0)
             ips->ipset_conf[ip_index].af = 0;
        else                     
             ips->ipset_conf[ip_index].af = AF_INET;
        ip_index++;
    }                
    if (ips != NULL) {
        ipset_sockopt_set(SOCKOPT_SET_IPSET_ADD, ips, ipset_size);
        rte_free(ips);
        FREE(buf);
        return 0;
    }

    FREE(buf);
    return -1;
}

static void ipset_read_conf_file(char *conf_file)
{
    FILE *stream;
    int i;
    char *confpath;
    char prev_path[CFG_FILE_MAX_BUF_SZ];

    glob_t globbuf = { .gl_offs = 0, };
    glob(conf_file, 0, NULL, &globbuf);

    for (i = 0; i < globbuf.gl_pathc; i++) {
        RTE_LOG(INFO, CFG_FILE, "Opening gfwip file '%s'.\n", globbuf.gl_pathv[i]);
        stream = fopen(globbuf.gl_pathv[i], "r");
        if (!stream) {
            RTE_LOG(WARNING, CFG_FILE, "Fail to open gfwip file '%s': %s.\n",
                    globbuf.gl_pathv[i], strerror(errno));
            return;
        }
        g_current_stream = stream;	
        if (getcwd(prev_path, CFG_FILE_MAX_BUF_SZ) != NULL) {
            confpath= strdup(globbuf.gl_pathv[i]);
            dirname(confpath);
            if (chdir(confpath) == 0) {
                if (ipset_parse_conf_file() < 0) {
                    RTE_LOG(ERR, IPSET, "Fail to parse gfwip conf\n");
                }
                if (chdir(prev_path) != 0)
                    RTE_LOG(ERR, CFG_FILE, "Fail to chdir()\n");
            }
            free(confpath);
        }
        fclose(stream);
    }

    globfree(&globbuf);
}

static int ipset_register_msg_cb(void)
{
    struct dpvs_msg_type msg_type;
    int err;

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_IPSET_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = ipset_add_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPSET, "%s: fail to register add msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_IPSET_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = ipset_del_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPSET, "%s: fail to register del msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_IPSET_FLUSH;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = ipset_flush_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPSET, "%s: fail to register flush msg.\n", __func__);
        return err;
    }
    return EDPVS_OK;
}

static int ipset_unregister_msg_cb(void)
{
    struct dpvs_msg_type msg_type;
    int err;

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_IPSET_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = ipset_add_msg_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPSET, "%s: fail to register add msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_IPSET_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = ipset_del_msg_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPSET, "%s: fail to register del msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_IPSET_FLUSH;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = ipset_flush_msg_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPSET, "%s: fail to register flush msg.\n", __func__);
        return err;
    }
    return EDPVS_OK;
}

int ipset_init(void)
{
    int err, i;
    lcoreid_t cid;

    this_num_ipset = 0;    

    for (i = 0; i < IPSET_TAB_SIZE; i++)
        INIT_LIST_HEAD(&this_ipset_table_lcore[i]);

    rte_eal_mp_remote_launch(ipset_lcore_init, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, IPSET, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
        }
    }
    
    if ((err = ipset_register_msg_cb()) != EDPVS_OK) {
        RTE_LOG(WARNING, IPSET, "fail to register ipset msg type.\n");
        ipset_unregister_msg_cb();
        return err;
    }

    if ((err = sockopt_register(&ipset_sockopts)) != EDPVS_OK) {
        ipset_unregister_msg_cb();
        return err;
    }
    ipset_read_conf_file(IPSET_CFG_FILE_NAME);

    return EDPVS_OK;
}

int ipset_term(void)
{
    int err;
    lcoreid_t cid;
    
    if ((err = ipset_unregister_msg_cb()) != EDPVS_OK)
        return err;
    if ((err = sockopt_unregister(&ipset_sockopts)) != EDPVS_OK)
        return err;

    rte_eal_mp_remote_launch(ipset_flush_lcore, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, IPSET, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
        }
    }

    return EDPVS_OK;
}

