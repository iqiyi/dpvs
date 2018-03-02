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

#define DPVS_NEIGH_TIMEOUT_DEF 60
#define DPVS_NEIGH_TIMEOUT_MIN 1
#define DPVS_NEIGH_TIMEOUT_MAX 3600

struct neighbour_entry {
    struct list_head arp_list;
    struct in_addr ip_addr;
    struct ether_addr eth_addr;
    struct netif_port *port;
    struct dpvs_timer timer;
    struct list_head queue_list;
    uint8_t flag;
    bool used;
    uint32_t que_num;
} __rte_cache_aligned;

struct neighbour_mbuf_entry {
    struct rte_mbuf *m;
    struct list_head neigh_mbuf_list;
} __rte_cache_aligned;

struct raw_neigh {
    struct in_addr ip_addr;
    struct ether_addr eth_addr;
    struct netif_port *port;
    bool add;
    uint8_t flag;
} __rte_cache_aligned;

#define NEIGHBOUR_BUILD      0x01
#define NEIGHBOUR_SEND       0x02
#define NEIGHBOUR_COMPLETED  0x04
#define NEIGHBOUR_HASHED     0x08
#define NEIGHBOUR_STATIC     0x10

#define NEIGH_PROCESS_MAC_RING_INTERVAL 100

/* params from config file */
static int arp_unres_qlen = ARP_ENTRY_BUFF_SIZE_DEF;
static int arp_timeout = DPVS_NEIGH_TIMEOUT_DEF;

static struct rte_ring *neigh_ring[DPVS_MAX_LCORE];

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
        arp_timeout = DPVS_NEIGH_TIMEOUT_DEF;
    }
    /* KW_TYPE_NORMAL keyword */
}

void install_neighbor_keywords(void)
{
    install_keyword_root("neigh_defs", NULL);
    install_keyword("unres_queue_length", unres_qlen_handler, KW_TYPE_INIT);
    install_keyword("timeout", timeout_handler, KW_TYPE_INIT);
}

static int  num_neighbours = 0;
static lcoreid_t g_cid = 0;
static lcoreid_t master_cid = 0;

static struct list_head neigh_table[DPVS_MAX_LCORE][ARP_TAB_SIZE];

static struct raw_neigh* neigh_ring_clone_entry(const struct neighbour_entry* neighbour, bool add);

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
    lcoreid_t cid = rte_lcore_id();
    if(!(neighbour->flag & NEIGHBOUR_HASHED)){
        list_add(&neighbour->arp_list, &neigh_table[cid][hashkey]);
        neighbour->flag |= NEIGHBOUR_HASHED;
        return EDPVS_OK;
    }

    return EDPVS_EXIST;
}

static inline int neigh_unhash(struct neighbour_entry *neighbour)
{
    int err;
    if((neighbour->flag & NEIGHBOUR_HASHED)){
        list_del(&neighbour->arp_list);
        neighbour->flag &= ~NEIGHBOUR_HASHED;
        err = EDPVS_OK;
    } else {
        err = EDPVS_NOTEXIST;
    }
    if (unlikely(err == EDPVS_NOTEXIST))
        RTE_LOG(DEBUG, NEIGHBOUR, "%s: arp entry not hashed.\n", __func__);
    return err;
}

static inline bool neigh_key_cmp(const struct neighbour_entry *neighbour,
                                 const void *key, const struct netif_port* port)
{
    return ((neighbour->ip_addr.s_addr == *(uint32_t*)key)
           &&(neighbour->port->id==port->id));
}

static void neigh_entry_expire(void *data)
{
    struct neighbour_entry *neighbour = data;
    struct timeval timeout;
    struct neighbour_mbuf_entry *mbuf, *mbuf_next;
    struct raw_neigh *mac_param;

    lcoreid_t cid = rte_lcore_id();

    if (neighbour->used)
        goto used;
    dpvs_timer_cancel(&neighbour->timer, false);
    neigh_unhash(neighbour);
        //release pkts saved in neighbour entry
    list_for_each_entry_safe(mbuf,mbuf_next,
              &neighbour->queue_list,neigh_mbuf_list){
        list_del(&mbuf->neigh_mbuf_list);
        rte_pktmbuf_free(mbuf->m);
        rte_free(mbuf);
    }

    if (cid  == g_cid) {
        mac_param = neigh_ring_clone_entry(neighbour, 0);
        if (mac_param) {
            int ret = rte_ring_enqueue(neigh_ring[master_cid], mac_param);
            if (unlikely(-EDQUOT == ret))
                RTE_LOG(WARNING, NEIGHBOUR, "%s: neigh ring quota exceeded\n",
                        __func__);
            else if (ret < 0) {
                rte_free(mac_param);
                RTE_LOG(WARNING, NETIF, "%s: neigh ring enqueue failed\n",
                        __func__);
            }
        }
        else
            RTE_LOG(WARNING, NEIGHBOUR, "%s: clone ring param faild\n", __func__);
    }

    rte_free(neighbour);

    return;

used:
    neighbour->used = 0;
//    RTE_LOG(INFO, NEIGHBOUR, "[%s] expire neighbour entry later\n", __func__);
    timeout.tv_sec = arp_timeout;
    timeout.tv_usec = 0;
    dpvs_timer_update(&neighbour->timer, &timeout, false);
    return;
}


static struct neighbour_entry *neigh_lookup_entry(const void *key, const struct netif_port* port, unsigned int hashkey)
{
    struct neighbour_entry *neighbour;
    lcoreid_t cid = rte_lcore_id();
    list_for_each_entry(neighbour, &neigh_table[cid][hashkey], arp_list){
        if(neigh_key_cmp(neighbour, key, port)){
    //        dpvs_timer_reset(&neighbour->timer, true);
            neighbour->used = 1;
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
    lcoreid_t cid = rte_lcore_id();

    if ((g_cid == cid) && !(neighbour->flag & NEIGHBOUR_STATIC)) {
        struct raw_neigh *mac_param;
        mac_param = neigh_ring_clone_entry(neighbour, 1);
        if (mac_param) {
            int ret = rte_ring_enqueue(neigh_ring[master_cid], mac_param);
            if (unlikely(-EDQUOT == ret))
                RTE_LOG(WARNING, NEIGHBOUR, "%s: neigh ring quota exceeded\n",
                        __func__);
            else if (ret < 0) {
                rte_free(mac_param);
                RTE_LOG(WARNING, NETIF, "%s: neigh ring enqueue failed\n",
                        __func__);
            }
        }
        else
            RTE_LOG(WARNING, NEIGHBOUR, "%s: clone ring param faild\n", __func__);
    }

    return EDPVS_OK;
}

static struct neighbour_entry *
neigh_add_table(uint32_t ipaddr, const struct ether_addr* eth_addr,
                struct netif_port* port, unsigned int hashkey, int flag)
{
    struct neighbour_entry *new_neighbour=NULL;
    struct in_addr *ip_addr = (struct in_addr*)&ipaddr;
    struct timeval delay;
    lcoreid_t cid = rte_lcore_id();

    delay.tv_sec = arp_timeout;
    delay.tv_usec = 0;
    new_neighbour = rte_zmalloc("new_neighbour_entry",
                    sizeof(struct neighbour_entry), RTE_CACHE_LINE_SIZE);
    if(new_neighbour == NULL)
        return NULL;

    rte_memcpy(&new_neighbour->ip_addr, ip_addr,
                sizeof(struct in_addr));
    new_neighbour->flag = flag;

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

    new_neighbour->used = 0;

    new_neighbour->que_num = 0;
    INIT_LIST_HEAD(&new_neighbour->queue_list);

    if (!(new_neighbour->flag & NEIGHBOUR_STATIC) && cid != master_cid) {
        dpvs_timer_sched(&new_neighbour->timer, &delay,
                neigh_entry_expire, new_neighbour, false);
    }

    if ((g_cid == cid) && !(new_neighbour->flag & NEIGHBOUR_STATIC)) {
        struct raw_neigh *mac_param;
        mac_param = neigh_ring_clone_entry(new_neighbour, 1);
        if (mac_param) {
            int ret = rte_ring_enqueue(neigh_ring[master_cid], mac_param);
            if (unlikely(-EDQUOT == ret))
                RTE_LOG(WARNING, NEIGHBOUR, "%s: neigh ring quota exceeded\n",
                        __func__);
            else if (ret < 0) {
                rte_free(mac_param);
                RTE_LOG(WARNING, NETIF, "%s: neigh ring enqueue failed\n",
                        __func__);
            }
        }
        else
            RTE_LOG(WARNING, NEIGHBOUR, "%s: clone ring param faild\n", __func__);
    }
    neigh_hash(new_neighbour, hashkey);

    return new_neighbour;
}

/***********************fill mac hdr before send pkt************************************/
static void neigh_fill_mac(struct neighbour_entry *neighbour, struct rte_mbuf *m)
{
    struct ether_hdr *eth;
    uint16_t pkt_type;

    m->l2_len = sizeof(struct ether_hdr);
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
        ether_addr_copy(&eth->s_addr, &eth->d_addr);
        rte_memcpy(&eth->s_addr, &port->addr, 6);
        arp->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);

        ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);//from to
        ether_addr_copy(&eth->s_addr, &arp->arp_data.arp_sha);

        ipaddr = arp->arp_data.arp_sip;
        arp->arp_data.arp_sip = arp->arp_data.arp_tip;
        arp->arp_data.arp_tip = ipaddr;
        m->l2_len = sizeof(struct ether_hdr);
        m->l3_len = sizeof(struct arp_hdr);
 
        netif_xmit(m, port);
        return EDPVS_OK;

    } else if(arp->arp_op == htons(ARP_OP_REPLY)) {
        ipaddr = arp->arp_data.arp_sip;
        hashkey = neigh_hashkey(ipaddr, port);
        neighbour = neigh_lookup_entry(&ipaddr, port, hashkey);
        if(neighbour) {
            neigh_edit(neighbour, &arp->arp_data.arp_sha, hashkey);
        } else {
            neighbour = neigh_add_table(ipaddr, &arp->arp_data.arp_sha, port, hashkey, 0);
            if(!neighbour){
                RTE_LOG(ERR, NEIGHBOUR, "[%s] add neighbour wrong\n", __func__);
                rte_pktmbuf_free(m);
                return EDPVS_NOMEM;
            }
        }
        neigh_send_mbuf_cach(neighbour);
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

    m = rte_pktmbuf_alloc(port->mbuf_pool);
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
    m->l2_len    = sizeof(struct ether_hdr);
    m->l3_len    = sizeof(struct arp_hdr);

    memset(&arp[1], 0, 18);

	dump_arp_hdr("send", arp, port->id);
    netif_xmit(m, port);
    return EDPVS_OK;
}

int neigh_resolve_output(struct in_addr *nexhop, struct rte_mbuf *m,
                         struct netif_port *port)
{
    struct neighbour_entry *neighbour;
    struct neighbour_mbuf_entry *m_buf;
    uint32_t src_ip;
    unsigned int hashkey;
    union inet_addr saddr, daddr;
    uint32_t nexhop_addr = nexhop->s_addr;

    if (port->flag & NETIF_PORT_FLAG_NO_ARP)
        return netif_xmit(m, port);

    hashkey = neigh_hashkey(nexhop_addr, port);
    neighbour = neigh_lookup_entry(&nexhop_addr, port, hashkey);

    if(neighbour){
        if(neighbour->flag & NEIGHBOUR_BUILD){
            if(neighbour->que_num > arp_unres_qlen){
                rte_pktmbuf_free(m);
                return EDPVS_DROP;
            }
            m_buf = rte_zmalloc("neigh_new_mbuf",
                               sizeof(struct neighbour_mbuf_entry), RTE_CACHE_LINE_SIZE);
            if(!m_buf){
                rte_pktmbuf_free(m);
                return EDPVS_DROP;
            }
            m_buf->m = m;
            list_add_tail(&m_buf->neigh_mbuf_list, &neighbour->queue_list);
            neighbour->que_num++;

            memset(&saddr, 0, sizeof(saddr));
            daddr.in.s_addr = nexhop_addr;
            inet_addr_select(AF_INET, port, &daddr, 0, &saddr);
            src_ip = saddr.in.s_addr;

            if(!src_ip){
                /* may have source address later,
                 * if not let timer to free neigh and it's mbuf queue. */
                return EDPVS_PKTSTOLEN;
            }
            if(neigh_send_arp(port, src_ip, nexhop_addr)){
                RTE_LOG(ERR, NEIGHBOUR, "[%s] send arp failed\n", __func__);
                return EDPVS_NOMEM;
            }
            return EDPVS_OK;
        }
        else if(neighbour->flag & NEIGHBOUR_COMPLETED){
            neigh_fill_mac(neighbour, m);
            netif_xmit(m, neighbour->port);
            return EDPVS_OK;
        }
        return EDPVS_IDLE;
    }
    else{
        neighbour = neigh_add_table(nexhop_addr, NULL, port, hashkey, 0);
        if(!neighbour){
            RTE_LOG(ERR, NEIGHBOUR, "[%s] add neighbour wrong\n", __func__);
            rte_pktmbuf_free(m);
            return EDPVS_NOMEM;
        }
        if(neighbour->que_num > arp_unres_qlen){
            rte_pktmbuf_free(m);
            return EDPVS_DROP;
        }
        m_buf = rte_zmalloc("neigh_new_mbuf",
                           sizeof(struct neighbour_mbuf_entry), RTE_CACHE_LINE_SIZE);
        if(!m_buf){
            rte_pktmbuf_free(m);
            return EDPVS_DROP;
        }
        m_buf->m = m;
        list_add_tail(&m_buf->neigh_mbuf_list, &neighbour->queue_list);
        neighbour->que_num++;

        memset(&saddr, 0, sizeof(saddr));
        daddr.in.s_addr = nexhop_addr;
        inet_addr_select(AF_INET, port, &daddr, 0, &saddr);
        src_ip = saddr.in.s_addr;

        if(!src_ip){
            /* may have source address later,
             * if not let timer to free neigh and it's mbuf queue. */
            return EDPVS_PKTSTOLEN;
        }

        if(neigh_send_arp(port, src_ip, nexhop_addr)){
            RTE_LOG(ERR, NEIGHBOUR, "[%s] send arp failed\n", __func__);
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


/****************************master core sync*******************************************/
#define MAC_RING_SIZE 2048

static int neigh_ring_init(void)
{
    char name_buf[RTE_RING_NAMESIZE];
    int socket_id;
    uint8_t cid;
    socket_id = rte_socket_id();
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        snprintf(name_buf, RTE_RING_NAMESIZE, "neigh_ring_c%d", cid);
        neigh_ring[cid] = rte_ring_create(name_buf, MAC_RING_SIZE, socket_id, RING_F_SC_DEQ);
        if (neigh_ring[cid] == NULL)
            rte_panic("create ring:%s failed!\n", name_buf);
    }
    return EDPVS_OK;
}

static struct raw_neigh* neigh_ring_clone_entry(const struct neighbour_entry* neighbour, bool add)
{
    struct raw_neigh* mac_param;
    mac_param = rte_zmalloc("mac_entry", sizeof(struct raw_neigh), RTE_CACHE_LINE_SIZE);
    if (mac_param == NULL)
        return NULL;
    rte_memcpy(&mac_param->ip_addr, &neighbour->ip_addr, sizeof(struct in_addr));
    mac_param->flag = neighbour->flag & ~NEIGHBOUR_HASHED;
    mac_param->port = neighbour->port;
    mac_param->add = add;
    /*just copy*/
    rte_memcpy(&mac_param->eth_addr, &neighbour->eth_addr, 6);
    return mac_param;
}

static struct raw_neigh* neigh_ring_clone_param(const struct dp_vs_neigh_conf *param, bool add)
{
    struct netif_port *port;
    struct raw_neigh* mac_param;
    port = netif_port_get_by_name(param->ifname);
    mac_param = rte_zmalloc("mac_entry", sizeof(struct raw_neigh), RTE_CACHE_LINE_SIZE);
    if (mac_param == NULL)
        return NULL;
    rte_memcpy(&mac_param->ip_addr, &param->ip_addr, sizeof(struct in_addr));
    mac_param->flag = param->flag | NEIGHBOUR_STATIC;
    mac_param->port = port;
    mac_param->add = add;
    rte_memcpy(&mac_param->eth_addr, &param->eth_addr, 6);
    return mac_param;
}

void neigh_process_ring(void *arg)
{
    struct raw_neigh *params[NETIF_MAX_PKT_BURST];
    uint16_t nb_rb;
    unsigned int hash;
    struct neighbour_entry *neigh;
    struct raw_neigh *param;
    lcoreid_t cid = rte_lcore_id();
    nb_rb = rte_ring_dequeue_burst(neigh_ring[cid], (void **)params, NETIF_MAX_PKT_BURST, NULL);
    if (nb_rb > 0) {
       int i;
       for (i = 0; i < nb_rb; i++) {
           param = params[i];
           hash = neigh_hashkey(param->ip_addr.s_addr, param->port);
           neigh = neigh_lookup_entry(&param->ip_addr.s_addr, param->port, hash);
           if (param->add) {
               if (neigh) {
                   neigh_edit(neigh, &param->eth_addr, hash);
               }
               else {
                   neigh = neigh_add_table(param->ip_addr.s_addr, &param->eth_addr,
                        param->port, hash, param->flag);
                   if ((cid == master_cid)&&(neigh)) {
                       num_neighbours++;
                   }
               }
           }
           else {
               if (neigh) {
                   if (!(neigh->flag & NEIGHBOUR_STATIC) &&
                       (cid != master_cid))
                       dpvs_timer_cancel(&neigh->timer, false);

                   neigh_unhash(neigh);
                   struct neighbour_mbuf_entry *mbuf, *mbuf_next;
                   list_for_each_entry_safe(mbuf, mbuf_next,
                                     &neigh->queue_list, neigh_mbuf_list) {
                       list_del(&mbuf->neigh_mbuf_list);
                       rte_pktmbuf_free(mbuf->m);
                       rte_free(mbuf);
                   }
                   rte_free(neigh);
                   if (cid == master_cid)
                       num_neighbours--;
               }
               else
                   RTE_LOG(WARNING, NEIGHBOUR, "%s: not exist\n", __func__);
           }
           rte_free(param);
       }
    }
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
        list_for_each_entry(entry, &neigh_table[master_cid][hash], arp_list) {
            neigh_fill_param(&array->addrs[off++], entry);
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
    lcoreid_t cid, i;
    cid = rte_lcore_id();
    struct raw_neigh *mac_param;


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
        neigh = neigh_lookup_entry(&param->ip_addr.in.s_addr, port, hash);
        if (neigh) {
            RTE_LOG(WARNING, NEIGHBOUR, "%s: already exist\n", __func__);
            return EDPVS_EXIST;
        }

        neigh = neigh_add_table(param->ip_addr.in.s_addr, &param->eth_addr,
                                port, hash, param->flag | NEIGHBOUR_STATIC);

        if (!neigh) {
            RTE_LOG(WARNING, NEIGHBOUR, "%s: no memory\n", __func__);
            return EDPVS_NOMEM;
        }


        for(i = 0; i < DPVS_MAX_LCORE; i++) {
            if ((i == cid) || (!is_lcore_id_valid(i)))
                continue;
            mac_param = neigh_ring_clone_param(param, 1);
            if (mac_param) {
                int ret = rte_ring_enqueue(neigh_ring[i], mac_param);
                if (unlikely(-EDQUOT == ret))
                    RTE_LOG(WARNING, NEIGHBOUR, "%s: neigh ring quota exceeded\n",
                    __func__);
                else if (ret < 0) {
                    rte_free(mac_param);
                    RTE_LOG(WARNING, NEIGHBOUR, "%s: neigh ring enqueue failed\n",
                    __func__);
                }
            }
            else
                RTE_LOG(WARNING, NEIGHBOUR, "%s: clone mac faild\n", __func__);
        }

        num_neighbours++;

        break;

    case SOCKOPT_SET_NEIGH_DEL:
        neigh = neigh_lookup_entry(&param->ip_addr.in.s_addr, port, hash);
        if (!neigh) {
            RTE_LOG(WARNING, NEIGHBOUR, "%s: not exist\n", __func__);
            return EDPVS_NOTEXIST;
        }

        neigh_unhash(neigh);
        list_for_each_entry_safe(mbuf, mbuf_next,
                                 &neigh->queue_list, neigh_mbuf_list) {
            list_del(&mbuf->neigh_mbuf_list);
            rte_pktmbuf_free(mbuf->m);
            rte_free(mbuf);
        }
        rte_free(neigh);
        num_neighbours--;

        for(i = 0; i < DPVS_MAX_LCORE; i++) {
            if ((i == cid) || (!is_lcore_id_valid(i)))
                continue;
            mac_param = neigh_ring_clone_param(param, 0);
            if (mac_param) {
                int ret = rte_ring_enqueue(neigh_ring[i], mac_param);
                if (unlikely(-EDQUOT == ret))
                    RTE_LOG(WARNING, NEIGHBOUR, "%s: neigh ring quota exceeded\n",
                    __func__);
                else if (ret < 0) {
                    rte_free(mac_param);
                    RTE_LOG(WARNING, NEIGHBOUR, "%s: neigh ring enqueue failed\n",
                    __func__);
                }
            }
            else
                RTE_LOG(WARNING, NEIGHBOUR, "%s: clone mac faild\n", __func__);
        }

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

static struct netif_lcore_loop_job neigh_sync_job;

static int arp_init(void)
{
    int i, j;
    int err;
    uint64_t lcore_mask;
    lcoreid_t cid;

    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        for (j = 0; j < ARP_TAB_SIZE; j++) {
            INIT_LIST_HEAD(&neigh_table[i][j]);
        }
    }


    /*choose one core to sync master*/
    netif_get_slave_lcores(NULL, &lcore_mask);

    for (cid = 0 ; cid < DPVS_MAX_LCORE; cid++) {
        if (lcore_mask & (1L << cid)) {
            g_cid = cid;
            break;
        }
    }

    master_cid = rte_lcore_id();

    arp_pkt_type.type = rte_cpu_to_be_16(ETHER_TYPE_ARP);
    if ((err = netif_register_pkt(&arp_pkt_type)) != EDPVS_OK)
        return err;
    if ((err = sockopt_register(&neigh_sockopts)) != EDPVS_OK)
        return err;

    neigh_ring_init();

    /*get static arp entry from master*/
    snprintf(neigh_sync_job.name, sizeof(neigh_sync_job.name) - 1, "%s", "neigh_sync");
    neigh_sync_job.func = neigh_process_ring;
    neigh_sync_job.data = NULL;
    neigh_sync_job.type = NETIF_LCORE_JOB_SLOW;
    neigh_sync_job.skip_loops = NEIGH_PROCESS_MAC_RING_INTERVAL;
    err = netif_lcore_loop_job_register(&neigh_sync_job);
    if (err != EDPVS_OK)
        return err;

    return EDPVS_OK;
}

int neigh_init(void)
{
    if(EDPVS_NOMEM == arp_init()){
        return EDPVS_NOMEM;
    }

    return EDPVS_OK;
}

int neigh_term(void)
{
    return EDPVS_OK;
}

