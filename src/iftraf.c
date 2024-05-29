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

#include <stdio.h>
#include <string.h>
#include "inet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "iftraf.h"
#include "conf/iftraf.h"
#include "vlan.h"
#include "scheduler.h"

#ifndef IFTRAF
#define IFTRAF
#define RTE_LOGTYPE_IFTRAF    RTE_LOGTYPE_USER1
#endif

#define IFTRAF_TOPN 20

#define IFTRAF_RING_SIZE  1024
#define IFTRAF_INTERVAL   1024

#define IFTRAF_PKT_DIR_IN 0
#define IFTRAF_PKT_DIR_OUT 1

#define IFTRAF_TBL_BITS          12
#define IFTRAF_TBL_SIZE          (1 << IFTRAF_TBL_BITS)
#define IFTRAF_TBL_MASK          (IFTRAF_TBL_SIZE - 1)

#define IFTRAF_IFTBL_BITS          10
#define IFTRAF_IFTBL_SIZE          (1 << IFTRAF_IFTBL_BITS)
#define IFTRAF_IFTBL_MASK          (IFTRAF_IFTBL_SIZE - 1)

#define IFTRAF_HISTORY_LENGTH  30
#define IFTRAF_TIME_INTERVAL 0x100000

static int history_pos = 0;
static int iftraf_ticket = 0;
bool iftraf_disable = true;

typedef struct sorted_list_node_tag {
    struct sorted_list_node_tag* next;
    void* data;
} sorted_list_node;

typedef struct {
    sorted_list_node root;
    int (*compare)(void*, void*);
    int sorted_list_num;
} sorted_list_type;

sorted_list_type iftraf_sorted_list;
sorted_list_type sorted_list[NETIF_MAX_PORTS];

static struct list_head *iftraf_tbl;
static struct list_head *iftraf_iftbl;

static struct rte_ring *iftraf_ring[DPVS_MAX_LCORE];

#define this_inpkts_count   (RTE_PER_LCORE(inpkts_count))
#define this_outpkts_count  (RTE_PER_LCORE(outpkts_count))

static RTE_DEFINE_PER_LCORE(uint32_t, inpkts_count);
static RTE_DEFINE_PER_LCORE(uint32_t, outpkts_count);

static uint32_t iftraf_tlb_rnd; /* hash random */

typedef enum {
    HASH_STATUS_OK,
    HASH_STATUS_KEY_NOT_FOUND
} hash_status_enum;

struct iftraf_pkt {
    uint8_t af;
    uint8_t proto;
    uint8_t dir;
    lcoreid_t cid;
    uint32_t pkt_len;
    union inet_addr saddr;
    union inet_addr daddr;
    uint16_t src_port;
    uint16_t dst_port;
    portid_t  devid;
    char ifname[IFNAMSIZ];
} __rte_cache_aligned;

struct iftraf_entry {
    struct list_head list;

    uint8_t af;
    uint8_t proto;
    lcoreid_t cid;
    portid_t devid;
    char ifname[IFNAMSIZ];

    union inet_addr saddr;
    union inet_addr daddr;
    uint16_t sport;
    uint16_t dport;

    uint32_t recv[IFTRAF_HISTORY_LENGTH];
    uint32_t sent[IFTRAF_HISTORY_LENGTH];

    uint32_t total_recv;
    uint32_t total_sent;
    int last_write;

} __rte_cache_aligned;


static inline uint32_t iftraf_tlb_hashkey(int af,
    const union inet_addr *saddr, uint16_t sport,
    const union inet_addr *daddr, uint16_t dport)
{
    switch (af) {
    case AF_INET:
        return rte_jhash_3words((uint32_t)saddr->in.s_addr,
                (uint32_t)daddr->in.s_addr,
                ((uint32_t)sport) << 16 | (uint32_t)dport,
                iftraf_tlb_rnd) & IFTRAF_TBL_MASK;

    case AF_INET6:
        {
            uint32_t vect[9];

            vect[0] = ((uint32_t)sport) << 16 | (uint32_t)dport;
            memcpy(&vect[1], &saddr->in6, 16);
            memcpy(&vect[5], &daddr->in6, 16);

            return rte_jhash_32b(vect, 9, iftraf_tlb_rnd) & IFTRAF_TBL_MASK;
        }

    default:
        RTE_LOG(DEBUG, IFTRAF, "%s: hashing unsupported protocol %d\n", __func__, af);
        return 0;
    }
}

static hash_status_enum iftraf_entry_get(uint32_t hash, struct iftraf_pkt *param, struct iftraf_entry **out_entry)
{
    struct iftraf_entry *entry;

    list_for_each_entry(entry, &iftraf_tbl[hash], list) {
        if (entry->sport == param->src_port && entry->dport == param->dst_port
            && inet_addr_equal(param->af, &entry->saddr, &param->saddr)
            && inet_addr_equal(param->af, &entry->daddr, &param->daddr)
            && entry->proto == param->proto
            && entry->af == param->af) {
            /* hit */
            *out_entry = entry;
            RTE_LOG(DEBUG, IFTRAF,
                "%s: [hit]\n", __func__);
            return HASH_STATUS_OK;
        }
    }
    RTE_LOG(DEBUG, IFTRAF,
        "%s: [not found]\n", __func__);

    return HASH_STATUS_KEY_NOT_FOUND;
}


static void history_rotate(void)
{
    uint32_t hash = 0;
    struct iftraf_entry *entry, *nxt;
    struct iftraf_entry *ifentry, *ifnxt;
    history_pos = (history_pos + 1) % IFTRAF_HISTORY_LENGTH;

    for(hash = 0; hash < IFTRAF_TBL_SIZE; hash++) {

        list_for_each_entry_safe(entry, nxt, &iftraf_tbl[hash], list) {
            /* no data in the last 20s */
            if (entry->last_write == history_pos) {
                list_del(&entry->list);
                if (entry->af == AF_INET) {
                    RTE_LOG(DEBUG, IFTRAF,
                        "%s:[v4] [history_pos : %d, cid:%d, proto:%u, src:%08X, dst:%08X, sp:%u, dp:%u]\n",
                        __func__, history_pos, entry->cid, entry->proto, entry->saddr.in.s_addr, entry->daddr.in.s_addr, entry->sport, entry->dport);
                }
                rte_free(entry);
            } else {
                entry->total_recv -= entry->recv[history_pos];
                entry->total_sent -= entry->sent[history_pos];
                entry->recv[history_pos] = 0;
                entry->sent[history_pos] = 0;
            }
        }
    }

    for(hash = 0; hash < IFTRAF_IFTBL_SIZE; hash++) {

        list_for_each_entry_safe(ifentry, ifnxt, &iftraf_iftbl[hash], list) {

            /* no data in the last 20s */
            if (ifentry->last_write == history_pos) {
                list_del(&ifentry->list);
                if (ifentry->af == AF_INET) {
                    RTE_LOG(DEBUG, IFTRAF,
                        "%s:[v4] [history_pos : %d, cid:%d, proto:%u, src:%08X, dst:%08X, sp:%u, dp:%u]\n",
                        __func__, history_pos, ifentry->cid, ifentry->proto, ifentry->saddr.in.s_addr, entry->daddr.in.s_addr, entry->sport, entry->dport);
                }
                rte_free(ifentry);
            } else {
                ifentry->total_recv -= ifentry->recv[history_pos];
                ifentry->total_sent -= ifentry->sent[history_pos];
                ifentry->recv[history_pos] = 0;
                ifentry->sent[history_pos] = 0;
            }
        }
    }
}

static int iftraf_entry_compare(void* aa, void* bb)
{
    struct iftraf_entry * a = (struct iftraf_entry *)aa;
    struct iftraf_entry * b = (struct iftraf_entry *)bb;

    return (a->total_recv + a->total_sent) > (b->total_recv + b->total_sent);
}

static void sorted_list_initialise(sorted_list_type* list)
{
    list->root.next = NULL;
    list->sorted_list_num = 0;
    list->compare = &iftraf_entry_compare;
}

static void insert_top_list(struct iftraf_entry *entry, sorted_list_type *p_iftraf_sorted_list)
{
    sorted_list_node *node, *p, *first;
    struct iftraf_entry *data;

    p = &(p_iftraf_sorted_list->root);

    if (p_iftraf_sorted_list->sorted_list_num == IFTRAF_TOPN && p_iftraf_sorted_list->compare(p->next->data, entry)) {
        struct iftraf_entry *firstentry = (struct iftraf_entry *)p->next->data;
        RTE_LOG(DEBUG, IFTRAF,
            "%s: no need to insert[%u: %u, %u: %u]\n",
             __func__, firstentry->total_recv, firstentry->total_sent, entry->total_recv, entry->total_sent);

        return;
    }

    while (p->next != NULL && p_iftraf_sorted_list->compare(entry, p->next->data) > 0) {
        p = p->next;
    }

    node = rte_zmalloc(NULL, sizeof(*node), RTE_CACHE_LINE_SIZE);
    if (node == NULL) {
        RTE_LOG(ERR, IFTRAF,
            "%s: no memory\n", __func__);
        return;
    }

    node->next = p->next;
    node->data = entry;
    p->next = node;
    RTE_LOG(DEBUG, IFTRAF,
        "%s: [insert list]cid : %d, sp : %u, dp : %u, recv : %u, sent : %u\n",
        __func__, entry->cid, ntohs(entry->sport), ntohs(entry->dport), entry->total_recv, entry->total_sent);
    if(p_iftraf_sorted_list->sorted_list_num < IFTRAF_TOPN)
        p_iftraf_sorted_list->sorted_list_num++;
    else {
        /* free the first node */
        p = &(p_iftraf_sorted_list->root);
        first = p->next;

        data = (struct iftraf_entry *)first->data;
        RTE_LOG(DEBUG, IFTRAF,
            "%s: [free first entry]cid : %d, sp : %u, dp : %u, recv : %u, sent : %u\n",
             __func__, data->cid, ntohs(data->sport), ntohs(data->dport), data->total_recv, data->total_sent);
        p->next = first->next;

        rte_free(first);
    }
}

static void list_merge(void)
{
    sorted_list_type *list;
    portid_t devid = 0;
    sorted_list_node *node, *p, *pp;
    uint32_t num = 0;

    pp = &(iftraf_sorted_list.root);
    for (devid = 0; devid < NETIF_MAX_PORTS; devid++) {

        list = &sorted_list[devid];
        p = &(list->root);
        while (p->next != NULL && num < list->sorted_list_num) {
            node = p->next;
            p->next = node->next;

            /*insert*/
            node->next = pp->next;
            pp->next = node;
            iftraf_sorted_list.sorted_list_num++;

            num++;
        }
        num = 0;
        list->sorted_list_num = 0;
    }
}

static void iftraf_sort_top(portid_t port_id)
{
    uint32_t hash = 0;
    struct iftraf_entry *entry, *nxt;
    struct iftraf_entry *ifentry, *ifnxt;

    if (port_id == NETIF_MAX_PORTS) {
        for (hash = 0; hash < IFTRAF_IFTBL_SIZE; hash++) {
            list_for_each_entry_safe(ifentry, ifnxt, &iftraf_iftbl[hash], list) {
                insert_top_list(ifentry, &sorted_list[ifentry->devid]);
            }
        }

        list_merge();

    } else if (port_id < NETIF_MAX_PORTS) {
        for (hash = 0; hash < IFTRAF_IFTBL_SIZE; hash++) {
            list_for_each_entry_safe(ifentry, ifnxt, &iftraf_iftbl[hash], list) {
                if (ifentry->devid == port_id) {
                    RTE_LOG(DEBUG, IFTRAF,
                        "%s: [devid : %u\n",
                         __func__, port_id);
                    insert_top_list(ifentry, &iftraf_sorted_list);
                }
            }
        }

    } else {
        for(hash = 0; hash < IFTRAF_TBL_SIZE; hash++) {
            list_for_each_entry_safe(entry, nxt, &iftraf_tbl[hash], list) {
                insert_top_list(entry, &iftraf_sorted_list);
            }
        }
    }
}

static void iftraf_addr_cpy(int af, union inet_addr *daddr, union inet_addr *saddr)
{
    if (af == AF_INET) {
        daddr->in.s_addr = saddr->in.s_addr;
    } else if (af == AF_INET6) {
        memcpy(daddr->in6.s6_addr, saddr->in6.s6_addr, 16);
    } else {
        RTE_LOG(DEBUG, IFTRAF,
            "%s: unsupported\n", __func__);
    }
}

int iftraf_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    struct iftraf_param_array *array;
    sorted_list_node *node, *p;
    struct iftraf_entry *entry;
    uint32_t off;
    struct netif_port *port = NULL;
    const struct dp_vs_iftraf_conf *cf;
    portid_t port_id = UINT16_MAX;

    if (iftraf_disable) {
        RTE_LOG(DEBUG, IFTRAF,
            "%s: iftraf disable\n",  __func__);
        return EDPVS_OK;
    }

    if (!conf || size < sizeof(struct dp_vs_iftraf_conf) || !out || !outsize)
        return EDPVS_INVAL;
    cf = conf;

    if (cf && strlen(cf->ifname)) {
        port = netif_port_get_by_name(cf->ifname);
        port_id = (port != NULL ) ? port->id : NETIF_MAX_PORTS;
        RTE_LOG(DEBUG, IFTRAF,
            "%s: ifname : %s, id = %d\n", __func__, cf->ifname, port_id);
    }

    /* sort iftraf */
    iftraf_sort_top(port_id);

    RTE_LOG(DEBUG, IFTRAF,
        "%s: sorted_list_num = %d\n", __func__, iftraf_sorted_list.sorted_list_num);

    *outsize = sizeof(struct iftraf_param_array) + \
               iftraf_sorted_list.sorted_list_num * sizeof(struct iftraf_param);
    *out = rte_calloc(NULL, 1, *outsize, RTE_CACHE_LINE_SIZE);
    if (!(*out)) {
        RTE_LOG(ERR, IFTRAF, "%s: no memory \n", __func__);
        return EDPVS_NOMEM;
    }

    array = *out;
    array->ntrafs = iftraf_sorted_list.sorted_list_num;
    off = 0;

    p = &(iftraf_sorted_list.root);
    while (p->next != NULL && off < iftraf_sorted_list.sorted_list_num) {
        node = p->next;
        p->next = node->next;

        entry = (struct iftraf_entry *)node->data;
        array->iftraf[off].af = entry->af;
        array->iftraf[off].proto = entry->proto;
        array->iftraf[off].cid = entry->cid;
        iftraf_addr_cpy(entry->af, &array->iftraf[off].saddr, &entry->saddr);
        iftraf_addr_cpy(entry->af, &array->iftraf[off].daddr, &entry->daddr);
        array->iftraf[off].sport = entry->sport;
        array->iftraf[off].dport = entry->dport;
        array->iftraf[off].total_recv = entry->total_recv;
        array->iftraf[off].total_sent = entry->total_sent;
        strcpy(array->iftraf[off].ifname, entry->ifname);

        if (AF_INET == entry->af) {
            RTE_LOG(DEBUG, IFTRAF,"%s: sip = %s, sport = %u, dip = %s, dport = %u\n",
                __func__, inet_ntoa(array->iftraf[off].saddr.in), ntohs(entry->sport), inet_ntoa(array->iftraf[off].daddr.in), ntohs(entry->dport));
        } else if (AF_INET6 == entry->af) {
            char src_addr[INET6_ADDRSTRLEN];
            char dst_addr[INET6_ADDRSTRLEN];

            inet_ntop(AF_INET6, &entry->saddr.in6, src_addr, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &entry->daddr.in6, dst_addr, INET6_ADDRSTRLEN);

            RTE_LOG(DEBUG, IFTRAF,"%s: sip = %s sport = %u, dip = %s, dport = %u\n",
                __func__, src_addr, ntohs(entry->sport), dst_addr, ntohs(entry->dport));
        } else {
            RTE_LOG(DEBUG, IFTRAF, "%s: unsupported\n", __func__);
        }

        RTE_LOG(DEBUG, IFTRAF,
            "%s: off : %u, cid : %d, proto: %u, total_recv: %u,  total_sent : %u\n",
            __func__, off, entry->cid, entry->proto, array->iftraf[off].total_recv, array->iftraf[off].total_sent);

        rte_free(node);

        off++;
    }

    iftraf_sorted_list.sorted_list_num = 0;
    return EDPVS_OK;
}

static void inline iftraf_tlb_add(struct iftraf_pkt *param)
{
    uint32_t hash;
    struct iftraf_entry *entry = NULL;

    hash = iftraf_tlb_hashkey(param->af, &param->saddr, param->src_port, &param->daddr,
               param->dst_port);

    if (iftraf_entry_get(hash, param, &entry) == HASH_STATUS_KEY_NOT_FOUND) {

        entry = rte_zmalloc(NULL, sizeof(struct iftraf_entry), RTE_CACHE_LINE_SIZE);
        if (entry == NULL) {
            RTE_LOG(ERR, IFTRAF,
                "%s: no memory\n", __func__);
            return;
        }

        memset(entry, 0, sizeof(struct iftraf_entry));
        entry->af = param->af;
        entry->cid = param->cid;
        entry->devid = param->devid;
        entry->proto = param->proto;
        iftraf_addr_cpy(param->af, &entry->saddr, &param->saddr);
        iftraf_addr_cpy(param->af, &entry->daddr, &param->daddr);
        entry->sport = param->src_port;
        entry->dport = param->dst_port;
        strcpy(entry->ifname, param->ifname);

        list_add(&entry->list, &iftraf_tbl[hash]);
    }

    if (param->af == AF_INET) {
        RTE_LOG(DEBUG, IFTRAF,
            "%s:[v4] dequeue iftraf_ring[cid:%d, proto:%u, src:%08X, dst:%08X, sp:%u, dp:%u, len:%u]\n",
            __func__, entry->cid, entry->proto, entry->saddr.in.s_addr,
            entry->daddr.in.s_addr, ntohs(entry->sport), ntohs(entry->dport), param->pkt_len);
    } else {
        RTE_LOG(DEBUG, IFTRAF,
            "%s:[v6] dequeue iftraf_ring[cid:%d, dir:%d, proto:%u, src:%08X %08X %08X %08X, dst:%08X %08X %08X %08X, sp:%u, dp:%u, len:%u]\n",
            __func__, entry->cid, param->dir, entry->proto,
            entry->saddr.in6.s6_addr32[0], entry->saddr.in6.s6_addr32[1],
            entry->saddr.in6.s6_addr32[2], entry->saddr.in6.s6_addr32[3],
            entry->daddr.in6.s6_addr32[0],entry->daddr.in6.s6_addr32[1],
            entry->daddr.in6.s6_addr32[2],entry->daddr.in6.s6_addr32[3],
            ntohs(entry->sport), ntohs(entry->dport), param->pkt_len);
    }

    /* Update record */
    entry->last_write = history_pos;
    if (param->dir == IFTRAF_PKT_DIR_IN) {
        entry->recv[history_pos] += param->pkt_len;
        entry->total_recv += param->pkt_len;
        RTE_LOG(DEBUG, IFTRAF,
            "%s: history_pos: %d, recv : %u, total_recv : %u\n", __func__, history_pos, entry->recv[history_pos], entry->total_recv);

    } else {
        entry->sent[history_pos] += param->pkt_len;
        entry->total_sent += param->pkt_len;

        RTE_LOG(DEBUG, IFTRAF,
            "%s: history_pos: %d: sent : %u, total_sent: %u\n", __func__, history_pos, entry->sent[history_pos], entry->total_sent);
    }
}

static inline unsigned iftraf_byif_hashkey(int af,
					const union inet_addr *addr,
					portid_t  devid)
{
    uint32_t addr_fold;

    addr_fold = inet_addr_fold(af, addr);

    if (!addr_fold) {
        RTE_LOG(DEBUG, IFTRAF, "%s: IP proto not support.\n", __func__);
        return 0;
    }

    return (ntohl(addr_fold) ^ (devid >> IFTRAF_IFTBL_BITS) ^ devid)
        & IFTRAF_IFTBL_MASK;
}

static hash_status_enum iftraf_ifentry_get(uint32_t hash, struct iftraf_pkt *param, struct iftraf_entry **out_entry)
{
    struct iftraf_entry *entry;

    list_for_each_entry(entry, &iftraf_iftbl[hash], list) {
        if (inet_addr_equal(param->af, &entry->saddr, &param->saddr)
            && entry->devid == param->devid
            && entry->af == param->af) {
            /* hit */
            *out_entry = entry;
            RTE_LOG(DEBUG, IFTRAF,
                "%s: [hit]\n", __func__);
            return HASH_STATUS_OK;
        }
    }
    RTE_LOG(DEBUG, IFTRAF,
        "%s: [not found]\n", __func__);

    return HASH_STATUS_KEY_NOT_FOUND;
}

static void inline iftraf_iftlb_add(struct iftraf_pkt *param)
{
    uint32_t hash;
    struct iftraf_entry *entry = NULL;

    hash = iftraf_byif_hashkey(param->af, &param->saddr, param->devid);

    if (iftraf_ifentry_get(hash, param, &entry) == HASH_STATUS_KEY_NOT_FOUND) {

        entry = rte_zmalloc(NULL, sizeof(struct iftraf_entry), RTE_CACHE_LINE_SIZE);
        if (entry == NULL) {
            RTE_LOG(ERR, IFTRAF,
                "%s: no memory\n", __func__);
            return;
        }

        memset(entry, 0, sizeof(struct iftraf_entry));
        entry->af = param->af;
        entry->cid = param->cid;
        entry->devid = param->devid;
        entry->proto = 0;//param->proto;
        iftraf_addr_cpy(param->af, &entry->saddr, &param->saddr);
        iftraf_addr_cpy(param->af, &entry->daddr, &param->daddr);
        entry->sport = 0;//param->src_port;
        entry->dport = 0;//param->dst_port;
        strcpy(entry->ifname, param->ifname);

        list_add(&entry->list, &iftraf_iftbl[hash]);
    }

    if (param->af == AF_INET) {
        RTE_LOG(DEBUG, IFTRAF,
            "%s:[v4] dequeue iftraf_ring[cid:%d, proto:%u, devid:%u, ifname:%s,src:%08X, dst:%08X, sp:%u, dp:%u, len:%u]\n",
            __func__, entry->cid, entry->proto, entry->devid, entry->ifname, entry->saddr.in.s_addr,
            entry->daddr.in.s_addr, ntohs(entry->sport), ntohs(entry->dport), param->pkt_len);
    } else {
        RTE_LOG(DEBUG, IFTRAF,
            "%s:[v6] dequeue iftraf_ring[cid:%d, dir:%d, proto:%u, devid:%u,  src:%08X %08X %08X %08X, dst:%08X %08X %08X %08X, sp:%u, dp:%u, len:%u]\n",
            __func__, entry->cid, param->dir, entry->proto, entry->devid,
            entry->saddr.in6.s6_addr32[0], entry->saddr.in6.s6_addr32[1],
            entry->saddr.in6.s6_addr32[2], entry->saddr.in6.s6_addr32[3],
            entry->daddr.in6.s6_addr32[0],entry->daddr.in6.s6_addr32[1],
            entry->daddr.in6.s6_addr32[2],entry->daddr.in6.s6_addr32[3],
            ntohs(entry->sport), ntohs(entry->dport), param->pkt_len);
    }

    /* Update record */
    entry->last_write = history_pos;
    if (param->dir == IFTRAF_PKT_DIR_IN) {
        entry->recv[history_pos] += param->pkt_len;
        entry->total_recv += param->pkt_len;
        RTE_LOG(DEBUG, IFTRAF,
        "%s: history_pos: %d, recv : %u, total_recv : %u\n", __func__, history_pos, entry->recv[history_pos], entry->total_recv);

    } else {
        entry->sent[history_pos] += param->pkt_len;
        entry->total_sent += param->pkt_len;

        RTE_LOG(DEBUG, IFTRAF,
            "%s: history_pos: %d: sent : %u, total_sent: %u\n", __func__, history_pos, entry->sent[history_pos], entry->total_sent);
    }
}


static void iftraf_process_ring(void *dummy)
{
    int i;
    uint16_t nb_rb;
    lcoreid_t cid;
    struct iftraf_pkt *param;
    struct iftraf_pkt *params[NETIF_MAX_PKT_BURST];

    if (likely(iftraf_disable)) {
        return;
    }

    iftraf_ticket++;
    if(iftraf_ticket % IFTRAF_TIME_INTERVAL == 0) {
        history_rotate();
        iftraf_ticket = 0;
    }

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!rte_lcore_is_enabled(cid)) {
            continue;
        }

        nb_rb = rte_ring_dequeue_burst(iftraf_ring[cid], (void **)params,
                    NETIF_MAX_PKT_BURST, NULL);

        if (nb_rb > 0) {
            for (i = 0; i < nb_rb; i++) {
                param = params[i];

                /* insert into iftraf table */
                iftraf_tlb_add(param);

                /* insert into iftraf table by if && source ip */
                iftraf_iftlb_add(param);
           }
        }
    }
}

static int iftraf_pkt_deliver(int af, struct rte_mbuf *mbuf, struct netif_port *dev, uint8_t dir)
{
    int ret;
    struct iftraf_pkt *pkt;
    __be16 _ports[2], *ports;
    lcoreid_t cid = rte_lcore_id();
    portid_t devid;

    if (af == AF_INET) {
        struct rte_ipv4_hdr *ip4h = ip4_hdr(mbuf);

        if (unlikely(ip4h->next_proto_id != IPPROTO_TCP &&
            ip4h->next_proto_id != IPPROTO_UDP &&
            ip4h->next_proto_id != IPPROTO_SCTP)) {
            RTE_LOG(DEBUG, IFTRAF,
                "%s: unspported proto[core: %d, proto: %d]\n",
                __func__, cid, ip4h->next_proto_id);
            return EDPVS_NOPROT;
        }

        ports = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_ports), _ports);
        if (!ports) {
            RTE_LOG(ERR, IFTRAF,
                "%s: invalid pkt[%d, %d]\n",
                __func__, cid, dir);
            return EDPVS_INVPKT;
        }

        pkt = rte_zmalloc("iftraf_inpkt", sizeof(struct iftraf_pkt), RTE_CACHE_LINE_SIZE);
        if (pkt == NULL) {
            RTE_LOG(ERR, IFTRAF,
                "%s: no memory[%d, %d]\n",
                __func__, cid, dir);
            return EDPVS_NOMEM;
        }

        if (dev->type == PORT_TYPE_VLAN) {
            struct vlan_dev_priv *vlan = netif_priv(dev);
            struct netif_port *real_dev = vlan->real_dev;
            RTE_LOG(DEBUG, IFTRAF, "%s: id = %u, ifname = %s, type=%d\n",
                __func__, real_dev->id,real_dev->name,real_dev->type);
            devid = real_dev->id;
            strcpy(pkt->ifname, real_dev->name);
        } else {
            devid = mbuf->port;
            strcpy(pkt->ifname, dev->name);
        }

        pkt->devid = devid;
        pkt->af = AF_INET;
        pkt->cid = cid;
        pkt->dir = dir;
        pkt->proto = ip4h->next_proto_id;
        if (dir == IFTRAF_PKT_DIR_IN) {
            pkt->saddr.in.s_addr = ip4h->src_addr;
            pkt->daddr.in.s_addr = ip4h->dst_addr;
            pkt->src_port = ports[0];
            pkt->dst_port = ports[1];
        } else {
            pkt->saddr.in.s_addr = ip4h->dst_addr;
            pkt->daddr.in.s_addr = ip4h->src_addr;
            pkt->src_port = ports[1];
            pkt->dst_port = ports[0];
        }

        pkt->pkt_len = mbuf->pkt_len;
        RTE_LOG(DEBUG, IFTRAF,
            "%s:[v4] enqueued to iftraf_ring[cid:%d, dir:%d, devid:%u, ifname:%s, proto:%u, src:%08X, dst:%08X, sp:%u, dp:%u, len:%u]\n",
            __func__, cid, dir, pkt->devid, pkt->ifname, pkt->proto, ip4h->src_addr, ip4h->dst_addr, ntohs(pkt->src_port), ntohs(pkt->dst_port), pkt->pkt_len);

    } else if (af == AF_INET6) {
        struct ip6_hdr *ip6h = ip6_hdr(mbuf);
        uint8_t ip6nxt = ip6h->ip6_nxt;

        if (unlikely(ip6nxt != IPPROTO_TCP &&
            ip6nxt != IPPROTO_UDP &&
            ip6nxt != IPPROTO_SCTP)) {
            RTE_LOG(DEBUG, IFTRAF,
                "%s: unspported proto[core: %d, proto: %d]\n",
                __func__, cid, ip6nxt);
            return EDPVS_NOPROT;
        }

        ports = mbuf_header_pointer(mbuf, ip6_hdrlen(mbuf), sizeof(_ports), _ports);
        if (!ports) {
            RTE_LOG(ERR, IFTRAF,
                "%s: invalid pkt[%d, %d]\n",
                __func__, cid, dir);
            return EDPVS_INVPKT;
        }

        pkt = rte_zmalloc("iftraf_inpkt", sizeof(struct iftraf_pkt), RTE_CACHE_LINE_SIZE);
        if (pkt == NULL) {
            RTE_LOG(ERR, IFTRAF,
                "%s: no memory[%d, %d]\n",
                __func__, cid, dir);
            return EDPVS_NOMEM;
        }

        if (dev->type == PORT_TYPE_VLAN) {
            struct vlan_dev_priv *vlan = netif_priv(dev);
            struct netif_port *real_dev = vlan->real_dev;
            RTE_LOG(DEBUG, IFTRAF, "%s: id = %u, ifname = %s, type=%d\n",
                __func__, real_dev->id,real_dev->name,real_dev->type);
            devid = real_dev->id;
            strcpy(pkt->ifname, real_dev->name);
        } else {
            devid = mbuf->port;
            strcpy(pkt->ifname, dev->name);
        }

        pkt->af = AF_INET6;
        pkt->devid = devid;
        pkt->cid = cid;
        pkt->dir = dir;
        pkt->proto = ip6nxt;
        if (dir == IFTRAF_PKT_DIR_IN) {
            pkt->saddr.in6 = ip6h->ip6_src;
            pkt->daddr.in6 = ip6h->ip6_dst;
            pkt->src_port = ports[0];
            pkt->dst_port = ports[1];
        } else {
            pkt->saddr.in6 = ip6h->ip6_dst;
            pkt->daddr.in6 = ip6h->ip6_src;
            pkt->src_port = ports[1];
            pkt->dst_port = ports[0];
        }
        pkt->pkt_len = mbuf->pkt_len;

        RTE_LOG(DEBUG, IFTRAF,
            "%s:[v6] enqueued to iftraf_ring[cid:%d, dir:%d, devid:%u,  proto:%u, src:%08X %08X %08X %08X, dst:%08X %08X %08X %08X, sp:%u, dp:%u, len:%u]\n",
            __func__, cid, dir, pkt->devid, pkt->proto,
            pkt->saddr.in6.s6_addr32[0], pkt->saddr.in6.s6_addr32[1],
            pkt->saddr.in6.s6_addr32[2], pkt->saddr.in6.s6_addr32[3],
            pkt->daddr.in6.s6_addr32[0],pkt->daddr.in6.s6_addr32[1],
            pkt->daddr.in6.s6_addr32[2],pkt->daddr.in6.s6_addr32[3],
            ntohs(pkt->src_port), ntohs(pkt->dst_port), pkt->pkt_len);
    } else {
        return EDPVS_INVPKT;
    }

    ret = rte_ring_enqueue(iftraf_ring[cid], pkt);
    if (ret < 0) {
        RTE_LOG(DEBUG, IFTRAF,
            "%s: failed to enqueue iftraf_ring[%d]\n",
            __func__, cid);
        rte_free(pkt);
        return EDPVS_DROP;
    }

    return EDPVS_OK;
}

int iftraf_pkt_in(int af, struct rte_mbuf *mbuf, struct netif_port *dev)
{
    if (likely(iftraf_disable)) {
        return EDPVS_OK;
    }

    this_inpkts_count++;
    if (this_inpkts_count % IFTRAF_INTERVAL == 0) {
        iftraf_pkt_deliver(af, mbuf, dev, IFTRAF_PKT_DIR_IN);
    }

    return EDPVS_OK;
}

int iftraf_pkt_out(int af, struct rte_mbuf *mbuf, struct netif_port *dev)
{
    if (likely(iftraf_disable)) {
        return EDPVS_OK;
    }

    this_outpkts_count++;
    if (this_outpkts_count % IFTRAF_INTERVAL == 0) {
        iftraf_pkt_deliver(af, mbuf, dev, IFTRAF_PKT_DIR_OUT);
    }

    return EDPVS_OK;
}


/*
 * master core allocates iftraf rings with the other lcores espectively.
 */
static int iftraf_ring_create(void)
{
    char name_buf[RTE_RING_NAMESIZE];
    int socket_id;
    lcoreid_t cid, ccid;

    socket_id = rte_socket_id();

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!rte_lcore_is_enabled(cid)) {
            continue;
        }

        snprintf(name_buf, RTE_RING_NAMESIZE,
            "iftraf_ring[%d]", cid);

        iftraf_ring[cid] =
            rte_ring_create(name_buf, IFTRAF_RING_SIZE, socket_id,
                            RING_F_SP_ENQ | RING_F_SC_DEQ);

        if (!iftraf_ring[cid]) {
            RTE_LOG(ERR, IFTRAF,
                "%s: failed to create iftraf_ring[%d]\n",
                 __func__, cid);
            for (ccid = 0; ccid < cid; ccid++) {
                if (iftraf_ring[ccid])
                    rte_ring_free(iftraf_ring[ccid]);
            }
            return EDPVS_NOMEM;
        }

        RTE_LOG(DEBUG, IFTRAF,
            "%s: success to create iftraf_ring[%d]\n",
            __func__, cid);
    }

    return EDPVS_OK;
}

static int iftraf_enable_func(void)
{
    int i;
    int err;
    lcoreid_t cid;

    if (iftraf_disable == false) {
        return EDPVS_OK;
    }

    err = iftraf_ring_create();
    if (err != EDPVS_OK) {
        return err;
    }

    iftraf_tbl = rte_malloc(NULL, sizeof(struct list_head) * IFTRAF_TBL_SIZE,
                    RTE_CACHE_LINE_SIZE);

    if (!iftraf_tbl) {
        RTE_LOG(ERR, IFTRAF,
            "%s: rte_malloc null\n",
            __func__);
        goto tbl_fail;
    }

    for (i = 0; i < IFTRAF_TBL_SIZE; i++)
        INIT_LIST_HEAD(&iftraf_tbl[i]);

    iftraf_iftbl = rte_malloc(NULL, sizeof(struct list_head) * IFTRAF_IFTBL_SIZE,
                      RTE_CACHE_LINE_SIZE);

    if (!iftraf_iftbl) {
        RTE_LOG(ERR, IFTRAF,
            "%s: rte_malloc null\n",
            __func__);
        goto iftbl_fail;
    }

    for (i = 0; i < IFTRAF_IFTBL_SIZE; i++)
        INIT_LIST_HEAD(&iftraf_iftbl[i]);

    iftraf_disable = false;
    RTE_LOG(INFO, IFTRAF,
        "%s: %s\n", __func__, "iftraf enabled");

    return EDPVS_OK;

iftbl_fail:
    if (iftraf_tbl)
        rte_free(iftraf_tbl);

tbl_fail:
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!rte_lcore_is_enabled(cid)) {
            continue;
        }
        if (iftraf_ring[cid])
            rte_ring_free(iftraf_ring[cid]);
        }

    return EDPVS_NOMEM;
}

static void iftraf_variable_reset(void)
{
    history_pos = 0;
    this_inpkts_count = 0;
    this_outpkts_count = 0;
}

static void iftraf_ring_free(void)
{
    lcoreid_t cid;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!rte_lcore_is_enabled(cid)) {
             continue;
        }
        if (iftraf_ring[cid]) {
            rte_ring_free(iftraf_ring[cid]);
        }

        RTE_LOG(DEBUG, IFTRAF,
            "%s: iftraf_ring free[%d]\n",
            __func__, cid);
    }
}


static int iftraf_disable_func(void)
{
    uint32_t hash;
    int i;
    uint16_t nb_rb;
    lcoreid_t cid;
    struct iftraf_pkt *param;
    struct iftraf_pkt *params[NETIF_MAX_PKT_BURST];
    struct iftraf_entry *entry, *nxt;
    int count = 0;

    if (iftraf_disable == true) {
        return EDPVS_OK;
    }

    iftraf_disable = true;

    /* dequeue iftraf ring and free elements */
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!rte_lcore_is_enabled(cid)) {
            continue;
        }

        nb_rb = rte_ring_dequeue_burst(iftraf_ring[cid], (void **)params,
                    NETIF_MAX_PKT_BURST, NULL);

        while (nb_rb > 0) {
            count += nb_rb;
            for (i = 0; i < nb_rb; i++) {
                param = params[i];
                rte_free(param);
            }

            nb_rb = rte_ring_dequeue_burst(iftraf_ring[cid], (void **)params,
                        NETIF_MAX_PKT_BURST, NULL);
        }

        RTE_LOG(DEBUG, IFTRAF,
            "%s: iftraf ring[%d] free [%d] pkts\n",
            __func__, cid, count);

        count = 0;

    }

    /* free iftraf ring */
    iftraf_ring_free();

    /* free tlb */
    if (iftraf_tbl) {
        count = 0;
        /* delete and free all entry added to iftraf_tbl */
        for(hash = 0; hash < IFTRAF_TBL_SIZE; hash++) {
            list_for_each_entry_safe(entry, nxt, &iftraf_tbl[hash], list) {
                list_del(&entry->list);
                rte_free(entry);
                count++;
            }
        }

        RTE_LOG(DEBUG, IFTRAF,
            "%s: iftraf_tbl free [%d]\n",
            __func__, count);

        rte_free(iftraf_tbl);
    }

    /* free tlb */
    if (iftraf_iftbl) {
        count = 0;
        /* delete and free all entry added to iftraf_tbl */
        for(hash = 0; hash < IFTRAF_IFTBL_SIZE; hash++) {
            list_for_each_entry_safe(entry, nxt, &iftraf_iftbl[hash], list) {
                list_del(&entry->list);
                rte_free(entry);
                count++;
            }
        }

        RTE_LOG(DEBUG, IFTRAF,
            "%s: iftraf_iftbl free [%d]\n",
            __func__, count);

        rte_free(iftraf_iftbl);
    }

    iftraf_variable_reset();
    RTE_LOG(INFO, IFTRAF,
        "%s: %s\n", __func__, "iftraf disabled");

    return EDPVS_OK;
}

static void iftraf_sorted_list_init(void) {
    portid_t devid = 0;
    sorted_list_initialise(&iftraf_sorted_list);

    for (devid = 0; devid < NETIF_MAX_PORTS; devid++) {
        sorted_list_initialise(&sorted_list[devid]);
    }
}

static int iftraf_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
     switch (opt) {
     case SOCKOPT_SET_IFTRAF_ADD:
          return iftraf_enable_func();
     case SOCKOPT_SET_IFTRAF_DEL:
          return iftraf_disable_func();

     default:
          return EDPVS_NOTSUPP;
     }
}


static struct dpvs_sockopts iftraf_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_IFTRAF_ADD,
    .set_opt_max    = SOCKOPT_SET_IFTRAF_DEL,
    .set            = iftraf_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_IFTRAF_SHOW,
    .get_opt_max    = SOCKOPT_GET_IFTRAF_SHOW,
    .get            = iftraf_sockopt_get,
};

static struct dpvs_lcore_job iftraf_job = {
    .name = "iftraf_ring_proc",
    .type = LCORE_JOB_LOOP,
    .func = iftraf_process_ring,
};

int iftraf_init(void)
{
    int err;

    iftraf_disable = true;

    iftraf_tlb_rnd = (uint32_t)random();

    iftraf_sorted_list_init();

    if ((err = dpvs_lcore_job_register(&iftraf_job, LCORE_ROLE_MASTER)) != EDPVS_OK)
        return err;

    if ((err = sockopt_register(&iftraf_sockopts)) != EDPVS_OK) {
        dpvs_lcore_job_unregister(&iftraf_job, LCORE_ROLE_MASTER);
        return err;
    }

    return EDPVS_OK;
}

int iftraf_term(void)
{
    int err;

    err = sockopt_unregister(&iftraf_sockopts);
    if (err != EDPVS_OK)
        return err;

    err = iftraf_disable_func();
    if (err != EDPVS_OK)
        return err;

    dpvs_lcore_job_unregister(&iftraf_job, LCORE_ROLE_MASTER);

    return EDPVS_OK;
}
