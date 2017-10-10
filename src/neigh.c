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
#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_spinlock.h>
#include <rte_arp.h>

#include "dpdk.h"
#include "parser/parser.h"
#include "netif.h"
#include "neigh.h"
#include "common.h"
#include "route.h"
#include "ctrl.h"
#include "conf/neigh.h"

#define ARP_TAB_BITS 8
#define ARP_TAB_SIZE (1 << ARP_TAB_BITS)
#define ARP_TAB_MASK (ARP_TAB_SIZE - 1)

#define ARP_ENTRY_BUFF_SIZE_DEF 128
#define ARP_ENTRY_BUFF_SIZE_MIN 16
#define ARP_ENTRY_BUFF_SIZE_MAX 8192

#define ARP_PKTPOOL_NB_MBUF_DEF 1023
#define ARP_PKTPOOL_NB_MBUF_MIN 63
#define ARP_PKTPOOL_NB_MBUF_MAX 32767

#define ARP_PKTPOOL_CACHE_MBUF_DEF 32
#define ARP_PKTPOOL_CACHE_MBUF_MIN 2
#define ARP_PKTPOOL_CACHE_MBUF_MAX 512

#define DPVS_NEIGH_TIMEOUT_DEF 60
#define DPVS_NEIGH_TIMEOUT_MIN 1
#define DPVS_NEIGH_TIMEOUT_MAX 3600

/* params from config file */
static int arp_unres_qlen = ARP_ENTRY_BUFF_SIZE_DEF;
static int arp_pktpool_size = ARP_PKTPOOL_NB_MBUF_DEF;
static int arp_pktpool_cache = ARP_PKTPOOL_CACHE_MBUF_DEF;
static int arp_timeout = DPVS_NEIGH_TIMEOUT_DEF;

static void unres_qlen_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int unres_qlen;

    assert(str);
    unres_qlen = atoi(str);

    if (arp_unres_qlen >= ARP_ENTRY_BUFF_SIZE_MIN &&
            arp_unres_qlen <= ARP_ENTRY_BUFF_SIZE_MAX) {
        RTE_LOG(INFO, NEIGHBOUR, "arp_unres_qlen = %d\n", unres_qlen);
        arp_unres_qlen = unres_qlen;
    } else {
        RTE_LOG(WARNING, NEIGHBOUR, "invalid arp_unres_qlen config %s, using default "
                "%d\n", str, ARP_ENTRY_BUFF_SIZE_DEF);
        arp_unres_qlen = ARP_ENTRY_BUFF_SIZE_DEF;
    }

    FREE_PTR(str);
}

static void pktpool_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int pktpool_size;

    assert(str);
    pktpool_size = atoi(str);
    if (pktpool_size >= ARP_PKTPOOL_NB_MBUF_MIN &&
            pktpool_size <= ARP_PKTPOOL_NB_MBUF_MAX) {
        is_power2(pktpool_size, 1, &pktpool_size);
        pktpool_size--;
        RTE_LOG(INFO, NEIGHBOUR, "arp_pktpool_size = %d(round to 2^n-1)\n", pktpool_size);
        arp_pktpool_size = pktpool_size;
    } else {
        RTE_LOG(WARNING, NEIGHBOUR, "invalid arp_pktpool_size config %s, using default "
                "%d\n", str, ARP_PKTPOOL_NB_MBUF_DEF);
        arp_pktpool_size = ARP_PKTPOOL_NB_MBUF_DEF;
    }

    FREE_PTR(str);
}

static void pktpool_cache_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int pktpool_cache;

    assert(str);
    pktpool_cache = atoi(str);
    if (pktpool_cache >= ARP_PKTPOOL_CACHE_MBUF_MIN &&
            pktpool_cache <= ARP_PKTPOOL_CACHE_MBUF_MAX) {
        is_power2(pktpool_cache, 0, &pktpool_cache);
        RTE_LOG(INFO, NEIGHBOUR, "arp_pktpool_cache = %d(round to 2^n)\n", pktpool_cache);
        arp_pktpool_cache = pktpool_cache;
    } else {
        RTE_LOG(WARNING, NEIGHBOUR, "invalid arp_pktpool_cache config %s, using default "
                "%d\n", str, ARP_PKTPOOL_CACHE_MBUF_DEF);
        arp_pktpool_cache = ARP_PKTPOOL_CACHE_MBUF_DEF;
    }

    FREE_PTR(str);
}

static void timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int timeout;

    assert(str);
    timeout = atoi(str);
    if (timeout >= DPVS_NEIGH_TIMEOUT_MIN && timeout <= DPVS_NEIGH_TIMEOUT_MAX) {
        RTE_LOG(INFO, NEIGHBOUR, "arp_timeout = %d\n", timeout);
        arp_timeout = timeout;
    } else {
        RTE_LOG(INFO, NEIGHBOUR, "invalid arp_timeout config %s, using default %d\n",
                str, DPVS_NEIGH_TIMEOUT_DEF);
        arp_timeout = DPVS_NEIGH_TIMEOUT_DEF;
    }
    FREE_PTR(str);
}

void neigh_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        arp_unres_qlen = ARP_ENTRY_BUFF_SIZE_DEF;
        arp_pktpool_cache = ARP_PKTPOOL_CACHE_MBUF_DEF;
        arp_pktpool_cache = ARP_PKTPOOL_CACHE_MBUF_DEF;
        arp_timeout = DPVS_NEIGH_TIMEOUT_DEF;
    }
    /* KW_TYPE_NORMAL keyword */
}

void install_neighbor_keywords(void)
{
    install_keyword_root("neigh_defs", NULL);
    install_keyword("unres_queue_length", unres_qlen_handler, KW_TYPE_INIT);
    install_keyword("pktpool_size", pktpool_size_handler, KW_TYPE_INIT);
    install_keyword("pktpool_cache", pktpool_cache_handler, KW_TYPE_INIT);
    install_keyword("timeout", timeout_handler, KW_TYPE_INIT);
}

static int  num_neighbours = 0;

static rte_spinlock_t neigh_lock[ARP_TAB_SIZE];

static struct list_head neigh_table[ARP_TAB_SIZE];

struct rte_mempool *neigh_pktmbuf_pool[NETIF_MAX_SOCKETS];

static void neigh_copy_cache(void);

#ifdef CONFIG_DPVS_NEIGH_DEBUG
static inline char *eth_addr_itoa(const struct ether_addr *src, char *dst, size_t size)
{
    snprintf(dst, size, "%02x:%02x:%02x:%02x:%02x:%02x", 
            src->addr_bytes[0],
            src->addr_bytes[1],
            src->addr_bytes[2],
            src->addr_bytes[3],
            src->addr_bytes[4],
            src->addr_bytes[5]);
    return dst;
} 

static void dump_arp_hdr(const char *msg, const struct arp_hdr *ah, portid_t port)
{
    const struct arp_ipv4 *aip4;
    char sha[18], tha[18];
    char sip[16], tip[16];
    lcoreid_t lcore;

    lcore = rte_lcore_id();

    fprintf(stderr, "%s lcore %d port%d arp hlen %u plen %u op %u",
            msg ? msg : "", lcore, port, ah->arp_hln, ah->arp_pln, ntohs(ah->arp_op));

    if (ah->arp_pro == htons(ETHER_TYPE_IPv4)) {
        aip4 = &ah->arp_data;
        eth_addr_itoa(&aip4->arp_sha, sha, sizeof(sha));
        eth_addr_itoa(&aip4->arp_tha, tha, sizeof(tha));
        inet_ntop(AF_INET, &aip4->arp_sip, sip, sizeof(sip));
        inet_ntop(AF_INET, &aip4->arp_tip, tip, sizeof(tip));
        fprintf(stderr, " sha %s sip %s tha %s tip %s", sha, sip, tha, tip);
    }
    fprintf(stderr, "\n");
}
#else
static inline void dump_arp_hdr(const char *msg, const struct arp_hdr *ah, portid_t port)
{
}
#endif

static inline unsigned int neigh_hashkey(uint32_t ip_addr, struct netif_port *port)
{
    return rte_be_to_cpu_32(ip_addr)&ARP_TAB_MASK;
}

static inline int neigh_hash(struct neighbour_entry *neighbour, unsigned int hashkey)
{
    if(!(neighbour->flag & NEIGHBOUR_HASHED)){
        list_add(&neighbour->arp_list, &neigh_table[hashkey]);
        neighbour->flag |= NEIGHBOUR_HASHED;
        rte_atomic32_inc(&neighbour->refcnt);
        return EDPVS_OK;
    }
    return EDPVS_EXIST;
}

static inline int neigh_unhash(struct neighbour_entry *neighbour)
{
    int err;
    if((neighbour->flag & NEIGHBOUR_HASHED)){
        if (rte_atomic32_read(&neighbour->refcnt) != 2){
            err = EDPVS_BUSY;
        } else {
            list_del(&neighbour->arp_list);
            neighbour->flag &= ~NEIGHBOUR_HASHED;
            rte_atomic32_dec(&neighbour->refcnt);
            err = EDPVS_OK;
        }
    } else {
        err = EDPVS_NOTEXIST;
    }
    if (unlikely(err == EDPVS_BUSY))
        RTE_LOG(DEBUG, NEIGHBOUR, "%s: arp entry is busy.\n", __func__);
    else if (unlikely(err == EDPVS_NOTEXIST))
        RTE_LOG(DEBUG, NEIGHBOUR, "%s: arp entry not hashed.\n", __func__);
    return err;
}

static inline bool neigh_key_cmp(const struct neighbour_entry *neighbour, 
                                 const void *key, const struct netif_port* port)
{
    return ((neighbour->ip_addr.s_addr == *(uint32_t*)key)
           &&(neighbour->port->id==port->id));
}

/*static void neigh_entry_put(struct neighbour_entry *neighbour)//for reset timer
{
    __neigh_entry_put(neighbour);
}
*/

static void neigh_entry_expire(void *data)
{
    struct neighbour_entry *neighbour = data;
    struct timeval timeout;
    struct neighbour_mbuf_entry *mbuf, *mbuf_next;
    
    rte_atomic32_inc(&neighbour->refcnt);
    if (neighbour->used)
        goto used;
    if (neighbour->flag & NEIGHBOUR_COMPLETED) {
        dpvs_timer_cancel(&neighbour->timer, true);
        goto used;
    }
    if (rte_atomic32_read(&neighbour->refcnt) == 2) {
        dpvs_timer_cancel(&neighbour->timer, true);
        neigh_unhash(neighbour);
        //release pkts saved in neighbour entry
        list_for_each_entry_safe(mbuf,mbuf_next,
                  &neighbour->queue_list,neigh_mbuf_list){
            list_del(&mbuf->neigh_mbuf_list);
            rte_pktmbuf_free(mbuf->m);
            rte_free(mbuf);
        }
        rte_atomic32_dec(&neighbour->refcnt);
        
        if (neighbour->cache[0])
            neighbour->cache[0]->neighbour = NULL;
        if (neighbour->cache[1])
            neighbour->cache[1]->neighbour = NULL; 

        rte_free(neighbour);
        num_neighbours--;
        return;
    }

used:
    neighbour->used = 0;
    /* RTE_LOG(INFO, NEIGHBOUR, "[%s] expire neighbour entry later\n", __func__); */
    timeout.tv_sec = arp_timeout;
    timeout.tv_usec = 0;
    dpvs_timer_update(&neighbour->timer, &timeout, true);
    rte_atomic32_dec(&neighbour->refcnt);
    return;
}


struct neighbour_entry *neigh_lookup_entry(const struct neigh_table *tbl, 
        const void *key, const struct netif_port* port, unsigned int hashkey)
{
    struct neighbour_entry *neighbour;
    list_for_each_entry(neighbour, &neigh_table[hashkey], arp_list){
        if(neigh_key_cmp(neighbour, key, port)){
    //        dpvs_timer_reset(&neighbour->timer, true);
            neighbour->used = 1;
            rte_atomic32_inc(&neighbour->refcnt);
            return neighbour;
        }
    }
    return NULL;
}

static int neigh_edit(struct neighbour_entry *neighbour, struct ether_addr* eth_addr, 
                      unsigned int hashkey) 
{
    rte_memcpy(&neighbour->eth_addr, eth_addr, 6); 
    neighbour->flag |= NEIGHBOUR_COMPLETED;
    neighbour->flag &= ~NEIGHBOUR_BUILD;
    return EDPVS_OK;
}

static struct neighbour_entry *
neigh_add_table(uint32_t ipaddr, const struct ether_addr* eth_addr,
                struct netif_port* port, unsigned int hashkey, int flag)
{
    struct neighbour_entry *new_neighbour=NULL;
    struct in_addr *ip_addr = (struct in_addr*)&ipaddr;
    struct timeval delay;
    delay.tv_sec = arp_timeout;
    delay.tv_usec = 0;
    new_neighbour = rte_zmalloc("new_neighbour_entry", 
                    sizeof(struct neighbour_entry), RTE_CACHE_LINE_SIZE);
    if(new_neighbour == NULL)
        return NULL;
    
    rte_memcpy(&new_neighbour->ip_addr, ip_addr, 
                sizeof(struct in_addr));
    new_neighbour->flag = flag;
    num_neighbours++;

    new_neighbour->cache[0] = NULL;
    new_neighbour->cache[1] = NULL;

    if(eth_addr){
        rte_memcpy(&new_neighbour->eth_addr, eth_addr, 6);
        new_neighbour->flag |= NEIGHBOUR_COMPLETED;
        new_neighbour->flag &= ~NEIGHBOUR_BUILD;
    }
    else{
        new_neighbour->flag |= NEIGHBOUR_BUILD;
        new_neighbour->flag &= ~NEIGHBOUR_COMPLETED;
    }

    new_neighbour->port = port;

    rte_atomic32_set(&new_neighbour->refcnt, 1);
    new_neighbour->used = 0;

    new_neighbour->que_num = 0;
    INIT_LIST_HEAD(&new_neighbour->queue_list);

    if (!(new_neighbour->flag & NEIGHBOUR_STATIC)) {
        dpvs_timer_sched(&new_neighbour->timer, &delay,
                neigh_entry_expire, new_neighbour, true); 
    }

    neigh_hash(new_neighbour, hashkey);
    return new_neighbour;
}

/***********************fill mac hdr before send pkt************************************/
static void neigh_fill_mac(struct neighbour_entry *neighbour, struct rte_mbuf *m)
{
    struct ether_hdr *eth;
    uint16_t pkt_type;
    eth = (struct ether_hdr *)rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct ether_hdr));
    ether_addr_copy(&neighbour->eth_addr,&eth->d_addr);
    ether_addr_copy(&neighbour->port->addr,&eth->s_addr);
    pkt_type = (uint16_t)m->packet_type;
    eth->ether_type = rte_cpu_to_be_16(pkt_type);
}

static void neigh_send_mbuf_cach(struct neighbour_entry *neighbour)
{
    struct neighbour_mbuf_entry *mbuf, *mbuf_next;
    struct rte_mbuf *m;
    
    list_for_each_entry_safe(mbuf, mbuf_next,
                             &neighbour->queue_list,neigh_mbuf_list){
        list_del(&mbuf->neigh_mbuf_list);
        m = mbuf->m;
        neigh_fill_mac(neighbour, m);
        netif_xmit(m, neighbour->port);
        neighbour->que_num--;
        rte_free(mbuf);
    }
}


int neigh_resolve_input(struct rte_mbuf *m, struct netif_port *port)
{
    
    struct arp_hdr *arp = rte_pktmbuf_mtod(m, struct arp_hdr *);
    struct ether_hdr *eth;

    uint32_t ipaddr;
    struct neighbour_entry *neighbour = NULL;
    unsigned int hashkey;
    struct route_entry *rt = NULL;

    rt = route4_local(arp->arp_data.arp_tip, port);
    if(!rt){
        return EDPVS_KNICONTINUE;
    }
    route4_put(rt);

    eth = (struct ether_hdr *)rte_pktmbuf_prepend(m,
                                     (uint16_t)sizeof(struct ether_hdr));

    if (rte_be_to_cpu_16(arp->arp_op) == ARP_OP_REQUEST) {

        ipaddr = arp->arp_data.arp_sip;
        hashkey = neigh_hashkey(ipaddr, port);
        rte_spinlock_lock(&neigh_lock[hashkey]);
        neighbour = arp_lookup(&ipaddr, port, hashkey);
        if(neighbour) {
            neigh_edit(neighbour, &arp->arp_data.arp_sha, hashkey);
            rte_atomic32_dec(&neighbour->refcnt);
        } else {
            neighbour = neigh_add_table(ipaddr, &arp->arp_data.arp_sha, port, hashkey, 0);
        
            if(!neighbour){
                 RTE_LOG(INFO, NEIGHBOUR, "[%s] add neighbour wrong\n", __func__);
                 rte_spinlock_unlock(&neigh_lock[hashkey]);
                 rte_pktmbuf_free(m);
                 return EDPVS_NOMEM;
            }
            rte_atomic32_dec(&neighbour->refcnt);
        }
        rte_spinlock_unlock(&neigh_lock[hashkey]);
        neigh_copy_cache();//synch cache

        ether_addr_copy(&eth->s_addr, &eth->d_addr);
        rte_memcpy(&eth->s_addr, &port->addr, 6);
        arp->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);

        ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);//from to
        ether_addr_copy(&eth->s_addr, &arp->arp_data.arp_sha);

        ipaddr = arp->arp_data.arp_sip;
        arp->arp_data.arp_sip = arp->arp_data.arp_tip;
        arp->arp_data.arp_tip = ipaddr;
        
        netif_xmit(m, port);
        return EDPVS_OK;
    } else if(arp->arp_op == htons(ARP_OP_REPLY)) {
        ipaddr = arp->arp_data.arp_sip;
        hashkey = neigh_hashkey(ipaddr, port);
        rte_spinlock_lock(&neigh_lock[hashkey]);
        neighbour = arp_lookup(&ipaddr, port, hashkey);
        if(neighbour) {
            neigh_edit(neighbour, &arp->arp_data.arp_sha, hashkey);
            rte_atomic32_dec(&neighbour->refcnt);
        } else {
            neighbour = neigh_add_table(ipaddr, &arp->arp_data.arp_sha, port, hashkey, 0);
            if(!neighbour){
                RTE_LOG(INFO, NEIGHBOUR, "[%s] add neighbour wrong\n", __func__);
                rte_spinlock_unlock(&neigh_lock[hashkey]);
                rte_pktmbuf_free(m);
                return EDPVS_NOMEM;
            }
            rte_atomic32_dec(&neighbour->refcnt);
        }
        neigh_send_mbuf_cach(neighbour);
        rte_spinlock_unlock(&neigh_lock[hashkey]);
        neigh_copy_cache();//synch cache
        return EDPVS_KNICONTINUE;
    } else {
        rte_pktmbuf_free(m);
        return EDPVS_DROP;
    }
}

static int neigh_send_arp(struct netif_port *port, uint32_t src_ip, uint32_t dst_ip)
{
    struct rte_mbuf *m;
    struct ether_hdr *eth;
    struct arp_hdr *arp;
    
    uint32_t addr;

    m = rte_pktmbuf_alloc(neigh_pktmbuf_pool[port->socket]);
    if(unlikely(m==NULL)){
        return EDPVS_NOMEM;
    }

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    arp = (struct arp_hdr *)&eth[1];

    memset(&eth->d_addr,0xFF,6);
    ether_addr_copy(&port->addr, &eth->s_addr);
    eth->ether_type = htons(ETHER_TYPE_ARP);

    memset(arp, 0, sizeof(struct arp_hdr));
    rte_memcpy(&arp->arp_data.arp_sha, &port->addr, 6);
    addr = src_ip;
    inetAddrCopy(&arp->arp_data.arp_sip, &addr);
    
    memset(&arp->arp_data.arp_tha, 0, 6);
    addr = dst_ip;
    inetAddrCopy(&arp->arp_data.arp_tip, &addr);
    
    arp->arp_hrd = htons(ARP_HRD_ETHER);
    arp->arp_pro = htons(ETHER_TYPE_IPv4);
    arp->arp_hln = 6;
    arp->arp_pln = 4;
    arp->arp_op  = htons(ARP_OP_REQUEST);
    m->pkt_len   = 60;
    m->data_len  = 60;

    memset(&arp[1], 0, 18);

	dump_arp_hdr("send", arp, port->id);
    netif_xmit(m, port);
    return EDPVS_OK;
}

static int neigh_resolve_output_lock(struct in_addr *nexhop, struct rte_mbuf *m, 
                         struct netif_port *port)
{
    struct neighbour_entry *neighbour;
    struct neighbour_mbuf_entry *m_buf;
    struct ipv4_hdr *iphdr;
    uint32_t src_ip;
    unsigned int hashkey;
    struct route_entry *rt=NULL;
#if 0 
    char daddr[16];char saddr[16];
    iphdr = rte_pktmbuf_mtod(m, struct ipv4_hdr *);
    src_ip = iphdr->src_addr;
    if (!inet_ntop(AF_INET, nexhop, daddr, sizeof(saddr)))
        return 1;
    if (!inet_ntop(AF_INET, &src_ip, saddr, sizeof(saddr)))
        return 1;
    printf("src %s ,dst %s\n",saddr,daddr);
#endif

    uint32_t nexhop_addr = nexhop->s_addr;
    hashkey = neigh_hashkey(nexhop_addr, port);
    rte_spinlock_lock(&neigh_lock[hashkey]);
    neighbour = arp_lookup(&nexhop_addr, port, hashkey);

    if(neighbour){
        if(neighbour->flag & NEIGHBOUR_BUILD){
            if(neighbour->que_num > arp_unres_qlen){
                rte_pktmbuf_free(m);
                rte_spinlock_unlock(&neigh_lock[hashkey]);
                rte_atomic32_dec(&neighbour->refcnt);
                return EDPVS_DROP;
            }
            m_buf = rte_zmalloc("neigh_new_mbuf", 
                               sizeof(struct neighbour_mbuf_entry), RTE_CACHE_LINE_SIZE);
            if(!m_buf){
                rte_pktmbuf_free(m);
                rte_spinlock_unlock(&neigh_lock[hashkey]);
                rte_atomic32_dec(&neighbour->refcnt);
                return EDPVS_DROP;
            }
            m_buf->m = m;
            list_add_tail(&m_buf->neigh_mbuf_list, &neighbour->queue_list);
            neighbour->que_num++;
            rte_spinlock_unlock(&neigh_lock[hashkey]);
            rte_atomic32_dec(&neighbour->refcnt);
            iphdr = rte_pktmbuf_mtod(m, struct ipv4_hdr *);
            rt = route4_local(iphdr->src_addr, port);
            if(rt){
                src_ip = iphdr->src_addr;
                route4_put(rt);
            }
            else{
                union inet_addr saddr, daddr;
                memset(&saddr, 0, sizeof(saddr));
                daddr.in.s_addr = nexhop_addr;
                inet_addr_select(AF_INET, port, &daddr, 0, &saddr);
                src_ip = saddr.in.s_addr;

                if(!src_ip){
                    /* may have source address later,
                     * if not let timer to free neigh and it's mbuf queue. */
                    return EDPVS_PKTSTOLEN;
                }
            }
            if(neigh_send_arp(port, src_ip, nexhop_addr)){
                RTE_LOG(INFO, NEIGHBOUR, "[%s] send arp failed\n", __func__);
                return EDPVS_NOMEM;
            }
            return EDPVS_OK;
        }
        else if(neighbour->flag & NEIGHBOUR_COMPLETED){
            neigh_fill_mac(neighbour, m);
            netif_xmit(m, neighbour->port);
            rte_spinlock_unlock(&neigh_lock[hashkey]);
            rte_atomic32_dec(&neighbour->refcnt);
            return EDPVS_OK;
        }
        rte_spinlock_unlock(&neigh_lock[hashkey]);
        rte_atomic32_dec(&neighbour->refcnt);
        return EDPVS_IDLE;
    }
    else{
        neighbour = neigh_add_table(nexhop_addr, NULL, port, hashkey, 0);
        if(!neighbour){
            RTE_LOG(INFO, NEIGHBOUR, "[%s] add neighbour wrong\n", __func__);
            rte_spinlock_unlock(&neigh_lock[hashkey]);
            return EDPVS_NOMEM; 
        }
        if(neighbour->que_num > arp_unres_qlen){
            rte_pktmbuf_free(m);
            rte_spinlock_unlock(&neigh_lock[hashkey]);
            rte_atomic32_dec(&neighbour->refcnt);
            return EDPVS_DROP;
        }
        m_buf = rte_zmalloc("neigh_new_mbuf",
                           sizeof(struct neighbour_mbuf_entry), RTE_CACHE_LINE_SIZE);
        if(!m_buf){
            rte_pktmbuf_free(m);
            rte_spinlock_unlock(&neigh_lock[hashkey]);
            rte_atomic32_dec(&neighbour->refcnt);
            return EDPVS_DROP;
        }
        m_buf->m = m;
        list_add_tail(&m_buf->neigh_mbuf_list, &neighbour->queue_list);
        neighbour->que_num++;
        rte_atomic32_dec(&neighbour->refcnt);
        rte_spinlock_unlock(&neigh_lock[hashkey]);
        iphdr = rte_pktmbuf_mtod(m, struct ipv4_hdr *);
        rt = route4_local(iphdr->src_addr, port);
        if(rt){
            src_ip = iphdr->src_addr;
            route4_put(rt);
        }   
        else{
            union inet_addr saddr, daddr;
            memset(&saddr, 0, sizeof(saddr));
            daddr.in.s_addr = nexhop_addr;
            inet_addr_select(AF_INET, port, &daddr, 0, &saddr);
            src_ip = saddr.in.s_addr;

            if(!src_ip){
                /* may have source address later,
                 * if not let timer to free neigh and it's mbuf queue. */
                return EDPVS_PKTSTOLEN;
            }
        }  
        
        if(neigh_send_arp(port, src_ip, nexhop_addr)){
            RTE_LOG(INFO, NEIGHBOUR, "[%s] send arp failed\n", __func__);
            return EDPVS_NOMEM;
        }
                
        return EDPVS_OK;        
    }
}

int neigh_gratuitous_arp(struct in_addr *src_ip, struct netif_port *port)
{
    uint32_t sip = src_ip->s_addr;
    return neigh_send_arp(port, sip, sip);
}

static struct pkt_type arp_pkt_type = { 
    //.type       = rte_cpu_to_be_16(ETHER_TYPE_ARP),
    .func       = neigh_resolve_input,
    .port       = NULL,
};


//neighbour cache code//

//make two cache table for switch, then the table can be lockless
static struct list_head neigh_cache_table[2][ARP_TAB_SIZE];
bool MASTER = 0;
rte_atomic32_t cache_refcnt[2];
static rte_spinlock_t cache_lock;

static struct neighbour_cache *neigh_cache_lookup(const uint32_t key, struct netif_port *port,
                                                  bool master)
{
    struct neighbour_cache *cache_entry;
    int hashkey;
    hashkey = neigh_hashkey(key, port);

    rte_atomic32_inc(&cache_refcnt[master]);
    list_for_each_entry(cache_entry, 
                        &neigh_cache_table[master][hashkey], arp_list) {
        if (cache_entry->ip_addr.s_addr == key) {
            return cache_entry;
        }
    }
    return NULL;
}

static int neigh_fill_slave_cache(struct neighbour_entry *entry, unsigned int hash)
{
    struct neighbour_cache *cache_entry;
    bool slave = !MASTER;
    if (entry->cache[slave]) {
        ether_addr_copy(&entry->eth_addr, &(entry->cache[slave])->eth_addr); 
        return EDPVS_OK;
    }    

    cache_entry = rte_malloc_socket(NULL, sizeof(*cache_entry), RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (cache_entry == NULL) {
        return EDPVS_NOMEM;
    }
    rte_memcpy(&cache_entry->ip_addr, &entry->ip_addr, sizeof(struct in_addr));
    ether_addr_copy(&entry->eth_addr, &cache_entry->eth_addr);
    cache_entry->port = entry->port;
    cache_entry->neighbour = entry;
    entry->cache[slave] = cache_entry;
    list_add(&cache_entry->arp_list, &neigh_cache_table[slave][hash]); 
    return EDPVS_OK;
}

static void neigh_copy_cache(void)
{
    int i = 0;
    struct neighbour_entry *entry;
    rte_spinlock_lock(&cache_lock);
    DPVS_WAIT_WHILE(rte_atomic32_read(&cache_refcnt[!MASTER]) > 0);
    for (i = 0; i < ARP_TAB_SIZE; i ++) {
        rte_spinlock_lock(&neigh_lock[i]);
        list_for_each_entry(entry, &neigh_table[i], arp_list) {
            rte_atomic32_inc(&entry->refcnt);
            if (entry->flag & NEIGHBOUR_COMPLETED)
                neigh_fill_slave_cache(entry, i);
            rte_atomic32_dec(&entry->refcnt);
        }
        rte_spinlock_unlock(&neigh_lock[i]);
    }
    MASTER = !MASTER;//switch master and slave cache table
    rte_spinlock_unlock(&cache_lock);// in case master is changed or two thread write  
}

static void neigh_cache_fill_mac(struct neighbour_cache *cache_entry, struct rte_mbuf *m) 
{
    struct ether_hdr *eth;
    uint16_t pkt_type;
    eth = (struct ether_hdr *)rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct ether_hdr));
    ether_addr_copy(&cache_entry->eth_addr,&eth->d_addr);
    ether_addr_copy(&cache_entry->port->addr,&eth->s_addr);
    pkt_type = (uint16_t)m->packet_type;
    eth->ether_type = rte_cpu_to_be_16(pkt_type);
}

int neigh_resolve_output(struct in_addr *nexhop, struct rte_mbuf *m,
                         struct netif_port *port)
{
    struct neighbour_cache *cache_entry;
    uint32_t nexhop_addr = nexhop->s_addr;
    bool save_master = MASTER;
    int err;

    cache_entry = neigh_cache_lookup(nexhop_addr, port, save_master);
    if (cache_entry) {
        neigh_cache_fill_mac(cache_entry, m);
        rte_atomic32_dec(&cache_refcnt[save_master]);
        err = netif_xmit(m, port);
    }
    else {
        rte_atomic32_dec(&cache_refcnt[save_master]);
        err = neigh_resolve_output_lock(nexhop, m, port);
    }
    return err;
}



/************************** used for dpip neighbour show***********************************/
static void neigh_fill_param(struct dp_vs_neigh_conf  *param,
                             const struct neighbour_entry *entry)
{
    param->af = AF_INET;
    param->ip_addr.in = entry->ip_addr;
    param->flag = entry->flag;
    if (entry->flag & NEIGHBOUR_COMPLETED)
        ether_addr_copy(&entry->eth_addr,&param->eth_addr);
    param->que_num = entry->que_num;
}

static int neigh_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    const struct dp_vs_neigh_conf *cf;
    struct dp_vs_neigh_conf_array *array;
    size_t hash, off;
    struct neighbour_entry *entry;

    if (conf && size >= sizeof(*cf))
        cf = conf;
    else
        cf = NULL;

    *outsize = sizeof(struct dp_vs_neigh_conf_array) + \
               num_neighbours * sizeof(struct dp_vs_neigh_conf);
    *out = rte_calloc(NULL, 1, *outsize, RTE_CACHE_LINE_SIZE);
    if (!(*out))
        return EDPVS_NOMEM;

    array = *out;
    array->n_neigh = num_neighbours;
    off = 0;
    for (hash = 0; hash < ARP_TAB_SIZE; hash ++){
        list_for_each_entry(entry, &neigh_table[hash], arp_list) {
            rte_spinlock_lock(&neigh_lock[hash]);
            rte_atomic32_inc(&entry->refcnt);
            neigh_fill_param(&array->addrs[off++], entry);
            rte_atomic32_dec(&entry->refcnt);
            rte_spinlock_unlock(&neigh_lock[hash]);
        }
    }
    return EDPVS_OK;
}

static int neigh_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct dp_vs_neigh_conf *param = conf;
    struct netif_port *port;
    struct neighbour_entry *neigh;
    unsigned int hash;
    struct neighbour_mbuf_entry *mbuf, *mbuf_next;

    if (!conf || size < sizeof(*param))
        return EDPVS_INVAL;

    if (param->af != AF_INET)
        return EDPVS_NOTSUPP;

    if (param->ip_addr.in.s_addr == htonl(INADDR_ANY))
        return EDPVS_INVAL;

    port = netif_port_get_by_name(param->ifname);
    if (!port) {
        RTE_LOG(WARNING, NEIGHBOUR, "%s: no such device: %s\n", 
                __func__, param->ifname);
        return EDPVS_INVAL;
    }

    hash = neigh_hashkey(param->ip_addr.in.s_addr, port);

    switch (opt) {
    case SOCKOPT_SET_NEIGH_ADD:
        rte_spinlock_lock(&neigh_lock[hash]);
        neigh = arp_lookup(&param->ip_addr.in.s_addr, port, hash);
        if (neigh) {
            rte_atomic32_dec(&neigh->refcnt);
            rte_spinlock_unlock(&neigh_lock[hash]);
            RTE_LOG(WARNING, NEIGHBOUR, "%s: already exist\n", __func__);
            return EDPVS_EXIST;
        }

        neigh = neigh_add_table(param->ip_addr.in.s_addr, &param->eth_addr,
                                port, hash, param->flag | NEIGHBOUR_STATIC);
        if (!neigh) {
            rte_spinlock_unlock(&neigh_lock[hash]);
            RTE_LOG(WARNING, NEIGHBOUR, "%s: no memory\n", __func__);
            return EDPVS_NOMEM;
        }

        rte_atomic32_dec(&neigh->refcnt);
        rte_spinlock_unlock(&neigh_lock[hash]);
        break;

    case SOCKOPT_SET_NEIGH_DEL:
        rte_spinlock_lock(&neigh_lock[hash]);
        neigh = arp_lookup(&param->ip_addr.in.s_addr, port, hash);
        if (!neigh) {
            rte_spinlock_unlock(&neigh_lock[hash]);
            RTE_LOG(WARNING, NEIGHBOUR, "%s: not exist\n", __func__);
            return EDPVS_NOTEXIST;
        }

        if (rte_atomic32_read(&neigh->refcnt) != 2) {
            rte_spinlock_unlock(&neigh_lock[hash]);
            RTE_LOG(WARNING, NEIGHBOUR, "%s: resource is busy\n", __func__);
            return EDPVS_BUSY;
        }

        if (!(neigh->flag & NEIGHBOUR_STATIC))
            dpvs_timer_cancel(&neigh->timer, true);

        neigh_unhash(neigh);
        list_for_each_entry_safe(mbuf, mbuf_next,
                                 &neigh->queue_list, neigh_mbuf_list) {
            list_del(&mbuf->neigh_mbuf_list);
            rte_pktmbuf_free(mbuf->m);
            rte_free(mbuf);
        }
        rte_free(neigh);
        num_neighbours--;

        rte_spinlock_unlock(&neigh_lock[hash]);
        break;

    default:
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static struct dpvs_sockopts neigh_sockopts = {
    .version     = SOCKOPT_VERSION,
    .get_opt_min = SOCKOPT_GET_NEIGH_SHOW,
    .get_opt_max = SOCKOPT_GET_NEIGH_SHOW,
    .get         = neigh_sockopt_get,

    .set_opt_min = SOCKOPT_SET_NEIGH_ADD,
    .set_opt_max = SOCKOPT_SET_NEIGH_DEL,
    .set         = neigh_sockopt_set,
};

static int arp_init(void)
{
    int i = 0, j = 0;
    int err;
      
    for (i = 0; i < ARP_TAB_SIZE; i ++) {
        INIT_LIST_HEAD(&neigh_table[i]);
        rte_spinlock_init(&neigh_lock[i]);
    }

    for (i = 0; i < 2; i ++) {
        for (j = 0; j < ARP_TAB_SIZE; j ++) {
            INIT_LIST_HEAD(&neigh_cache_table[i][j]);
        }
    }

    arp_tbl = rte_zmalloc("new_neigh_table",sizeof(struct neigh_table),RTE_CACHE_LINE_SIZE);
    if(arp_tbl == NULL){
        return EDPVS_NOMEM;
    }   
    arp_tbl->proto = 0;
    arp_tbl->neigh_entry_head = &neigh_table[0];

    arp_pkt_type.type = rte_cpu_to_be_16(ETHER_TYPE_ARP);
    if ((err = netif_register_pkt(&arp_pkt_type)) != EDPVS_OK)
        return err;
    if ((err = sockopt_register(&neigh_sockopts)) != EDPVS_OK)
        return err;

    rte_atomic32_set(&cache_refcnt[MASTER], 0);
    rte_atomic32_set(&cache_refcnt[!MASTER], 0);

    return EDPVS_OK;
}

int neigh_init(void)
{
    int i;
    char poolname[32];
    if(EDPVS_NOMEM == arp_init()){
        return EDPVS_NOMEM;
    } 

    for (i = 0; i < NETIF_MAX_SOCKETS; i++) {
        snprintf(poolname, sizeof(poolname), "neigh_mbuf_pool_%d", i);
        neigh_pktmbuf_pool[i] = rte_pktmbuf_pool_create(poolname,
                arp_pktpool_size, arp_pktpool_cache, 0, RTE_MBUF_DEFAULT_BUF_SIZE, i);
        if(!neigh_pktmbuf_pool[i]){
            return EDPVS_NOMEM;
        }
    }
    return EDPVS_OK;
}

int neigh_term(void)
{
    /*for (int i=0; i<ARP_TAB_SIZE; i++){
         
    } */
    return -1; 
}

