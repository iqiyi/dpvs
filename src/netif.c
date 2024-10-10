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
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include "dpdk.h"
#include "conf/common.h"
#include "netif.h"
#include "netif_addr.h"
#include "conf/netif_addr.h"
#include "vlan.h"
#include "ctrl.h"
#include "list.h"
#include "kni.h"
#include <rte_version.h>
#include "conf/netif.h"
#include "timer.h"
#include "parser/parser.h"
#include "neigh.h"
#include "scheduler.h"
#include "netif_flow.h"

#include <rte_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ipvs/redirect.h>
#ifdef CONFIG_ICMP_REDIRECT_CORE
#include "icmp.h"
#endif

#define NETIF_PKTPOOL_NB_MBUF_DEF   65535
#define NETIF_PKTPOOL_NB_MBUF_MIN   1023
#define NETIF_PKTPOOL_NB_MBUF_MAX   134217727
int netif_pktpool_nb_mbuf = NETIF_PKTPOOL_NB_MBUF_DEF;

#define NETIF_PKTPOOL_MBUF_CACHE_DEF    256
#define NETIF_PKTPOOL_MBUF_CACHE_MIN    32
#define NETIF_PKTPOOL_MBUF_CACHE_MAX    8192
int netif_pktpool_mbuf_cache = NETIF_PKTPOOL_MBUF_CACHE_DEF;

#define NETIF_NB_RX_DESC_DEF    256
#define NETIF_NB_RX_DESC_MIN    16
#define NETIF_NB_RX_DESC_MAX    8192

#define NETIF_NB_TX_DESC_DEF    512
#define NETIF_NB_TX_DESC_MIN    16
#define NETIF_NB_TX_DESC_MAX    8192

#define NETIF_PKT_PREFETCH_OFFSET   3
#define NETIF_ISOL_RXQ_RING_SZ_DEF  1048576 // 1M bytes

#define ARP_RING_SIZE 2048

#define RETA_CONF_SIZE  (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)

/* physical nic id = phy_pid_base + index */
static portid_t phy_pid_base = 0;
static portid_t phy_pid_end = -1; // not inclusive
/* bond device id = bond_pid_base + index */
static portid_t bond_pid_base = -1;
static portid_t bond_pid_end = -1; // not inclusive

static portid_t port_id_end = 0;

static uint16_t g_nports;

/*for arp process*/
static struct rte_ring *arp_ring[DPVS_MAX_LCORE];

#define NETIF_BOND_MODE_DEF         BONDING_MODE_ROUND_ROBIN
#define NETIF_BOND_NUMA_NODE_DEF    0

struct port_conf_stream {
    int port_id;
    char name[32];
    char kni_name[32];

    int rx_queue_nb;
    int rx_desc_nb;
    char rss[32];
    int mtu;

    int tx_queue_nb;
    int tx_desc_nb;

    bool promisc_mode;
    bool allmulticast;

    struct list_head port_list_node;
};

struct bond_options {
    bool dedicated_queues_enable;
};

struct bond_conf_stream {
    int port_id;
    char name[32];
    char kni_name[32];
    int mode;
    int numa_node;
    char primary[32];
    char slaves[NETIF_MAX_BOND_SLAVES][32];
    struct bond_options options;
    struct list_head bond_list_node;
};

struct queue_conf_stream {
    char port_name[32];
    int rx_queues[NETIF_MAX_QUEUES];
    int tx_queues[NETIF_MAX_QUEUES];
    int isol_rxq_lcore_ids[NETIF_MAX_QUEUES];
    int isol_rxq_ring_sz;
    struct list_head queue_list_node;
};

struct worker_conf_stream {
    int cpu_id;
    char name[32];
    char type[32];
    struct list_head port_list;
    struct list_head worker_list_node;
};

static struct list_head port_list;      /* device configurations from cfgfile */
static struct list_head bond_list;      /* bonding configurations from cfgfile */
static struct list_head worker_list;    /* lcore configurations from cfgfile */

#define NETIF_PORT_TABLE_BITS 8
#define NETIF_PORT_TABLE_BUCKETS (1 << NETIF_PORT_TABLE_BITS)
#define NETIF_PORT_TABLE_MASK (NETIF_PORT_TABLE_BUCKETS - 1)
static struct list_head port_tab[NETIF_PORT_TABLE_BUCKETS]; /* hashed by id */
static struct list_head port_ntab[NETIF_PORT_TABLE_BUCKETS]; /* hashed by name */
/* Note: Lockless, NIC can only be registered on initialization stage and
 *       unregistered on cleanup stage
 */

#define NETIF_CTRL_BUFFER_LEN     4096

/* function declarations */
static void kni_lcore_loop(void *dummy);

bool is_physical_port(portid_t pid)
{
    return pid >= phy_pid_base && pid < phy_pid_end;
}

bool is_bond_port(portid_t pid)
{
    return pid >= bond_pid_base && pid < bond_pid_end;
}

void netif_physical_port_range(portid_t *start, portid_t *end)
{
    if (start)
        *start = phy_pid_base;
    if (end)
        *end = phy_pid_end;
}

void netif_bond_port_range(portid_t *start, portid_t *end)
{
    if (start)
        *start = bond_pid_base;
    if (end)
        *end = bond_pid_end;
}

bool is_lcore_id_valid(lcoreid_t cid)
{
    if (unlikely(cid >= DPVS_MAX_LCORE))
        return false;

    return ((cid == rte_get_main_lcore()) ||
            (cid == g_kni_lcore_id) ||
            (g_slave_lcore_mask & (1L << cid)) ||
            (g_isol_rx_lcore_mask & (1L << cid)));
}

static bool is_lcore_id_fwd(lcoreid_t cid)
{
    if (unlikely(cid >= DPVS_MAX_LCORE))
        return false;

    return ((cid == rte_get_main_lcore()) ||
            (g_slave_lcore_mask & (1L << cid)));
}

static inline struct port_conf_stream *get_port_conf_stream(const char *name)
{
    struct port_conf_stream *current_cfg;

    list_for_each_entry(current_cfg, &port_list, port_list_node) {
        if (!strcmp(name, current_cfg->name))
            return current_cfg;
    }

    return NULL;
}

static void netif_defs_handler(vector_t tokens)
{
    struct port_conf_stream *port_cfg, *port_cfg_next;
    struct bond_conf_stream *bond_cfg, *bond_cfg_next;

    list_for_each_entry_safe(port_cfg, port_cfg_next, &port_list, port_list_node) {
        list_del(&port_cfg->port_list_node);
        rte_free(port_cfg);
    }

    list_for_each_entry_safe(bond_cfg, bond_cfg_next, &bond_list, bond_list_node) {
        list_del(&bond_cfg->bond_list_node);
        rte_free(bond_cfg);
    }
}

static void pktpool_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int pktpool_size;

    assert(str);
    pktpool_size = atoi(str);
    if (pktpool_size < NETIF_PKTPOOL_NB_MBUF_MIN ||
            pktpool_size > NETIF_PKTPOOL_NB_MBUF_MAX) {
        RTE_LOG(WARNING, NETIF, "invalid pktpool_size %s, using default %d\n",
                str, NETIF_PKTPOOL_NB_MBUF_DEF);
        netif_pktpool_nb_mbuf = NETIF_PKTPOOL_NB_MBUF_DEF;
    } else {
        is_power2(pktpool_size, 1, &pktpool_size);
        RTE_LOG(INFO, NETIF, "pktpool_size = %d (round to 2^n-1)\n", pktpool_size - 1);
        netif_pktpool_nb_mbuf = pktpool_size - 1;
    }

    FREE_PTR(str);
}

static void pktpool_cache_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int cache_size;

    assert(str);
    cache_size = atoi(str);
    if (cache_size < NETIF_PKTPOOL_MBUF_CACHE_MIN ||
            cache_size > NETIF_PKTPOOL_MBUF_CACHE_MAX) {
        RTE_LOG(WARNING, NETIF, "invalid pktpool_cache_size %s, using default %d\n",
                str, NETIF_PKTPOOL_MBUF_CACHE_DEF);
        netif_pktpool_mbuf_cache = NETIF_PKTPOOL_MBUF_CACHE_DEF;
    } else {
        is_power2(cache_size, 0, &cache_size);
        RTE_LOG(INFO, NETIF, "pktpool_cache_size = %d (round to 2^n)\n", cache_size);
        netif_pktpool_mbuf_cache = cache_size;
    }

    FREE_PTR(str);
}

#ifdef CONFIG_DPVS_FDIR
static enum rte_fdir_mode g_fdir_mode = RTE_FDIR_MODE_PERFECT;

static void fdir_mode_handler(vector_t tokens)
{
    char *mode, *str = set_value(tokens);

    assert(str);
    mode = strlwr(str);

    if (!strncmp(mode, "perfect", sizeof("perfect")))
        g_fdir_mode = RTE_FDIR_MODE_PERFECT;
    else if (!strncmp(mode, "signature", sizeof("signature")))
        g_fdir_mode = RTE_FDIR_MODE_SIGNATURE;
    else {
        RTE_LOG(WARNING, NETIF, "invalid fdir_mode %s, using default %s\n",
                mode, "perfect");
        g_fdir_mode = RTE_FDIR_MODE_PERFECT;
    }
    RTE_LOG(INFO, NETIF, "g_fdir_mode = %s\n", mode);

    FREE_PTR(str);
}
#endif

static void device_handler(vector_t tokens)
{
    assert(VECTOR_SIZE(tokens) >= 1);

    char *str;
    struct port_conf_stream *port_cfg =
        rte_zmalloc(NULL, sizeof(struct port_conf_stream), RTE_CACHE_LINE_SIZE);
    if (!port_cfg) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        return;
    }

    port_cfg->port_id = -1;
    str = VECTOR_SLOT(tokens, 1);
    RTE_LOG(INFO, NETIF, "netif device config: %s\n", str);
    strncpy(port_cfg->name, str, sizeof(port_cfg->name));
    port_cfg->rx_queue_nb = -1;
    port_cfg->tx_queue_nb = -1;
    port_cfg->rx_desc_nb = NETIF_NB_RX_DESC_DEF;
    port_cfg->tx_desc_nb = NETIF_NB_TX_DESC_DEF;
    port_cfg->mtu = NETIF_DEFAULT_ETH_MTU;

    port_cfg->promisc_mode = false;
    port_cfg->allmulticast = false;
    strncpy(port_cfg->rss, "tcp", sizeof(port_cfg->rss));

    list_add(&port_cfg->port_list_node, &port_list);
}

static void rx_queue_number_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int rx_queues;
    struct port_conf_stream *current_device = list_entry(port_list.next,
            struct port_conf_stream, port_list_node);

    assert(str);
    rx_queues = atoi(str);
    if (rx_queues < 0 || rx_queues > NETIF_MAX_QUEUES) {
        RTE_LOG(WARNING, NETIF, "invalid %s:rx_queue_number %s, using default %d\n",
                current_device->name, str, NETIF_MAX_QUEUES);
        current_device->rx_queue_nb = NETIF_MAX_QUEUES;
    } else {
        RTE_LOG(WARNING, NETIF, "%s:rx_queue_number = %d\n",
                current_device->name, rx_queues);
        current_device->rx_queue_nb = rx_queues;
    }

    FREE_PTR(str);
}

static void rx_desc_nb_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int desc_nb;
    struct port_conf_stream *current_device = list_entry(port_list.next,
            struct port_conf_stream, port_list_node);

    assert(str);
    desc_nb = atoi(str);
    if (desc_nb < NETIF_NB_RX_DESC_MIN || desc_nb > NETIF_NB_RX_DESC_MAX) {
        RTE_LOG(WARNING, NETIF, "invalid %s:nb_rx_desc %s, using default %d\n",
                current_device->name, str, NETIF_NB_RX_DESC_DEF);
        current_device->rx_desc_nb = NETIF_NB_RX_DESC_DEF;
    } else {
        is_power2(desc_nb, 0, &desc_nb);
        RTE_LOG(INFO, NETIF, "%s:nb_rx_desc = %d (round to 2^n)\n",
                current_device->name, desc_nb);
        current_device->rx_desc_nb = desc_nb;
    }

    FREE_PTR(str);
}

static void rss_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    struct port_conf_stream *current_device = list_entry(port_list.next,
            struct port_conf_stream, port_list_node);

    assert(str);
    if (!strcmp(str, "all") || !strcmp(str, "ip") || !strcmp(str, "tcp") || !strcmp(str, "udp")
            || !strcmp(str, "sctp") || !strcmp(str, "ether") || !strcmp(str, "port") || !strcmp(str, "tunnel")
            || (strstr(str, "|") && str[0] != '|')) {
        RTE_LOG(INFO, NETIF, "%s:rss = %s\n", current_device->name, str);
        strncpy(current_device->rss, str, sizeof(current_device->rss));
    } else {
        RTE_LOG(WARNING, NETIF, "invalid %s:rss %s, using default rss_tcp\n",
                current_device->name, str);
        strncpy(current_device->rss, "tcp", sizeof(current_device->rss));
    }

    FREE_PTR(str);
}

static void tx_queue_number_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int tx_queues;
    struct port_conf_stream *current_device = list_entry(port_list.next,
            struct port_conf_stream, port_list_node);

    assert(str);
    tx_queues = atoi(str);
    if (tx_queues < 0 || tx_queues > NETIF_MAX_QUEUES) {
        RTE_LOG(WARNING, NETIF, "invalid %s:tx_queue_number %s, using default %d\n",
                current_device->name, str, NETIF_MAX_QUEUES);
        current_device->tx_queue_nb = NETIF_MAX_QUEUES;
    } else {
        RTE_LOG(INFO, NETIF, "%s:tx_queue_number = %d\n",
                current_device->name, tx_queues);
        current_device->tx_queue_nb = tx_queues;
    }

    FREE_PTR(str);
}

static void tx_desc_nb_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int desc_nb;
    struct port_conf_stream *current_device = list_entry(port_list.next,
            struct port_conf_stream, port_list_node);

    assert(str);
    desc_nb = atoi(str);
    if (desc_nb < NETIF_NB_TX_DESC_MIN || desc_nb > NETIF_NB_TX_DESC_MAX) {
        RTE_LOG(WARNING, NETIF, "invalid nb_tx_desc %s, using default %d\n",
                str, NETIF_NB_TX_DESC_DEF);
        current_device->tx_desc_nb = NETIF_NB_TX_DESC_DEF;
    } else {
        is_power2(desc_nb, 0, &desc_nb);
        RTE_LOG(INFO, NETIF, "%s:nb_tx_desc = %d (round to 2^n)\n",
                current_device->name, desc_nb);
        current_device->tx_desc_nb = desc_nb;
    }

    FREE_PTR(str);
}

static void promisc_mode_handler(vector_t tokens)
{
    struct port_conf_stream *current_device = list_entry(port_list.next,
            struct port_conf_stream, port_list_node);
    current_device->promisc_mode = true;
}

static void allmulticast_handler(vector_t tokens)
{
    struct port_conf_stream *current_device = list_entry(port_list.next,
            struct port_conf_stream, port_list_node);
    current_device->allmulticast = true;
}

static void custom_mtu_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int mtu = 0;
    struct port_conf_stream *current_device = list_entry(port_list.next,
            struct port_conf_stream, port_list_node);

    assert(str);
    mtu = atoi(str);
    if (mtu <= 0 || mtu > NETIF_MAX_ETH_MTU) {
        RTE_LOG(WARNING, NETIF, "invalid %s:MTU %s, using default %d\n",
                current_device->name, str, NETIF_DEFAULT_ETH_MTU);
        current_device->mtu= NETIF_DEFAULT_ETH_MTU;
    } else {
        RTE_LOG(INFO, NETIF, "%s:mtu = %d\n",
                current_device->name, mtu);
        current_device->mtu = mtu;
    }

    FREE_PTR(str);

}
static void kni_name_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    struct port_conf_stream *current_device = list_entry(port_list.next,
            struct port_conf_stream, port_list_node);

    assert(str);
    RTE_LOG(INFO, NETIF, "%s:kni_name = %s\n",current_device->name, str);
    strncpy(current_device->kni_name, str, sizeof(current_device->kni_name));

    FREE_PTR(str);
}

static void bonding_handler(vector_t tokens)
{
    assert(VECTOR_SIZE(tokens) >= 1);

    char *str;
    struct bond_conf_stream *bond_cfg =
        rte_zmalloc(NULL, sizeof(struct bond_conf_stream), RTE_CACHE_LINE_SIZE);
    if (!bond_cfg) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        return;
    }

    bond_cfg->port_id = -1;
    str = VECTOR_SLOT(tokens, 1);
    RTE_LOG(INFO, NETIF, "netif bonding config: %s\n", str);
    strncpy(bond_cfg->name, str, sizeof(bond_cfg->name));
    bond_cfg->mode = NETIF_BOND_MODE_DEF;
    bond_cfg->numa_node = NETIF_BOND_NUMA_NODE_DEF;
    bond_cfg->options.dedicated_queues_enable = true;

    list_add(&bond_cfg->bond_list_node, &bond_list);
}

static void bonding_mode_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int mode;
    struct bond_conf_stream *current_bond = list_entry(bond_list.next,
            struct bond_conf_stream, bond_list_node);

    assert(str);
    mode = atoi(str);
    switch (mode) {
        case BONDING_MODE_ROUND_ROBIN:
        case BONDING_MODE_ACTIVE_BACKUP:
        case BONDING_MODE_BALANCE:
        case BONDING_MODE_BROADCAST:
        case BONDING_MODE_8023AD:
        case BONDING_MODE_TLB:
        case BONDING_MODE_ALB:
            RTE_LOG(INFO, NETIF, "bonding %s:mode=%d\n", current_bond->name, mode);
            current_bond->mode = mode;
            break;
        default:
            RTE_LOG(WARNING, NETIF, "invalid bonding %s:mode %d, using default %d\n",
                    current_bond->name, mode, NETIF_BOND_MODE_DEF);
            current_bond->mode = NETIF_BOND_MODE_DEF;
    }

    FREE_PTR(str);
}

static void bonding_slave_handler(vector_t tokens)
{
    int ii;
    char *str = set_value(tokens);
    struct bond_conf_stream *current_bond = list_entry(bond_list.next,
            struct bond_conf_stream, bond_list_node);

    assert(str);
    if (get_port_conf_stream(str)) {
        for (ii = 0; ii < NETIF_MAX_BOND_SLAVES; ii++) {
            if (!current_bond->slaves[ii][0]) {
                strncpy(current_bond->slaves[ii], str, sizeof(current_bond->slaves[ii]));
                RTE_LOG(INFO, NETIF, "bonding %s:slave%d=%s\n", current_bond->name, ii, str);
                break;
            }
        }
    } else {
        RTE_LOG(ERR, NETIF, "invalid bonding %s:salve %s, skip ...\n",
                current_bond->name, str);
    }

    FREE_PTR(str);
}

static void bonding_primary_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    struct bond_conf_stream *current_bond = list_entry(bond_list.next,
            struct bond_conf_stream, bond_list_node);

    assert(str);
    if (get_port_conf_stream(str)) {
        RTE_LOG(INFO, NETIF, "bonding %s:primary=%s\n", current_bond->name, str);
        strncpy(current_bond->primary, str, sizeof(current_bond->primary));
    } else {
        RTE_LOG(WARNING, NETIF, "invalid bonding %s:primary %s, skip ...\n",
                current_bond->name, str);
    }

    FREE_PTR(str);
}

static void bonding_numa_node_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int numa_node;
    struct bond_conf_stream *current_bond = list_entry(bond_list.next,
            struct bond_conf_stream, bond_list_node);
    assert(str);

    numa_node = atoi(str);
    if (numa_node >= get_numa_nodes()) {
        RTE_LOG(WARNING, NETIF, "invalid bonding %s:numa_node %d, using default %d\n",
                current_bond->name, numa_node, NETIF_BOND_NUMA_NODE_DEF);
        current_bond->mode = NETIF_BOND_NUMA_NODE_DEF;
    } else {
        RTE_LOG(INFO, NETIF, "bonding %s:numa_node=%d\n", current_bond->name, numa_node);
        current_bond->numa_node = numa_node;
    }

    FREE_PTR(str);
}

static void bonding_kni_name_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    struct bond_conf_stream *current_bond = list_entry(bond_list.next,
            struct bond_conf_stream, bond_list_node);

    assert(str);
    RTE_LOG(INFO, NETIF, "bonding %s:kni_name=%s\n", current_bond->name, str);
    strncpy(current_bond->kni_name, str, sizeof(current_bond->kni_name));

    FREE_PTR(str);
}

static inline char * get_bonding_option_value(char *token)
{
    char *ptr, *saveptr = NULL, *ret = token;

    if (!token)
        return NULL;

    for (ptr = token; ret == token; ptr = NULL)
        ret = strtok_r(ptr, "=", &saveptr);

    return ret;
}

static void bonding_options_handler(vector_t tokens)
{
    char *str;
    char *opt, *val, *ptr, *saveptr = NULL;

    str = set_value(tokens);
    struct bond_conf_stream *current_bond = list_entry(bond_list.next,
            struct bond_conf_stream, bond_list_node);

    assert(str);
    RTE_LOG(INFO, NETIF, "bonding %s options: %s\n", current_bond->name, str);

    for (ptr = str; ;ptr = NULL) {
        opt = strtok_r(ptr, ";", &saveptr);
        if (opt == NULL)
            break;
        val = get_bonding_option_value(opt);

        if (!strcmp(opt, "dedicated_queues")) {
            if (current_bond->mode != BONDING_MODE_8023AD || !val) {
                RTE_LOG(WARNING, NETIF, "invalid bonding %s mode 4 option: %s, value: %s\n",
                        current_bond->name, opt, val ?: "null");
                continue;
            }
            if (!strcasecmp(val, "on") || !strcasecmp(val, "enable"))
                current_bond->options.dedicated_queues_enable = true;
            else if (!strcasecmp(val, "off") || !strcasecmp(val, "disable"))
                current_bond->options.dedicated_queues_enable = false;
            else
                RTE_LOG(WARNING, NETIF, "invalid bonding %s option value: %s=%s\n",
                        current_bond->name, opt, val);
        } else {
            RTE_LOG(WARNING, NETIF, "unsupported bonding %s option: %s\n",
                    current_bond->name, opt);
        }
    }

    FREE_PTR(str);
}

static void worker_defs_handler(vector_t tokens)
{
    struct worker_conf_stream *worker_cfg, *worker_cfg_next;
    struct queue_conf_stream *queue_cfg, *queue_cfg_next;

    list_for_each_entry_safe(worker_cfg, worker_cfg_next, &worker_list,
            worker_list_node) {
        list_del(&worker_cfg->worker_list_node);
        list_for_each_entry_safe(queue_cfg, queue_cfg_next, &worker_cfg->port_list,
                queue_list_node) {
            list_del(&queue_cfg->queue_list_node);
            rte_free(queue_cfg);
        }
        rte_free(worker_cfg);
    }
}

static void worker_handler(vector_t tokens)
{
    assert(VECTOR_SIZE(tokens) >= 1);

    char *str;
    struct worker_conf_stream *worker_cfg = rte_malloc(NULL,
            sizeof(struct worker_conf_stream), RTE_CACHE_LINE_SIZE);
    if (!worker_cfg) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        return;
    }

    INIT_LIST_HEAD(&worker_cfg->port_list);

    str = VECTOR_SLOT(tokens, 1);
    RTE_LOG(INFO, NETIF, "netif worker config: %s\n", str);
    strncpy(worker_cfg->name, str, sizeof(worker_cfg->name));

    list_add(&worker_cfg->worker_list_node, &worker_list);
}

static void worker_type_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);

    assert(str);
    if (!strcmp(str, "master") || !strcmp(str, "slave")
        || !strcmp(str, "kni")) {
        RTE_LOG(INFO, NETIF, "%s:type = %s\n", current_worker->name, str);
        strncpy(current_worker->type, str, sizeof(current_worker->type));
    } else {
        RTE_LOG(WARNING, NETIF, "invalid %s:type %s, using default %s\n",
                current_worker->name, str, "slave");
        strncpy(current_worker->type, "slave", sizeof(current_worker->type));
    }

    FREE_PTR(str);
}

static void cpu_id_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int cpu_id;
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);

    assert(str);
    if (strspn(str, "0123456789") != strlen(str)) {
        RTE_LOG(WARNING, NETIF, "invalid %s:cpu_id %s, using default 0\n",
                current_worker->name, str);
        current_worker->cpu_id = 0;
    } else {
        cpu_id = atoi(str);
        RTE_LOG(INFO, NETIF, "%s:cpu_id = %d\n", current_worker->name, cpu_id);
        current_worker->cpu_id = cpu_id;

        if (!strcmp(current_worker->type, "kni"))
            g_kni_lcore_id = cpu_id;
    }

    FREE_PTR(str);
}

#ifdef CONFIG_ICMP_REDIRECT_CORE
static void cpu_icmp_redirect_handler(vector_t tokens)
{
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);

    RTE_LOG(INFO, NETIF, "%s(%d) used to redirect icmp packets\n",
        current_worker->name, current_worker->cpu_id);
    g_icmp_redirect_lcore_id = current_worker->cpu_id;
}
#endif

static void worker_port_handler(vector_t tokens)
{
    assert(VECTOR_SIZE(tokens) >= 1);

    char *str;
    int ii;
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);
    struct queue_conf_stream *queue_cfg = rte_malloc(NULL,
            sizeof(struct queue_conf_stream), RTE_CACHE_LINE_SIZE);
    if (!queue_cfg) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        return;
    }

    for (ii = 0; ii < NETIF_MAX_QUEUES; ii++) {
        queue_cfg->tx_queues[ii] = NETIF_MAX_QUEUES;
        queue_cfg->rx_queues[ii] = NETIF_MAX_QUEUES;
        queue_cfg->isol_rxq_lcore_ids[ii] = NETIF_LCORE_ID_INVALID;
    }
    queue_cfg->isol_rxq_ring_sz = NETIF_ISOL_RXQ_RING_SZ_DEF;

    str = VECTOR_SLOT(tokens, 1);
    RTE_LOG(INFO, NETIF, "worker %s:%s queue config\n", current_worker->name, str);
    strncpy(queue_cfg->port_name, str, sizeof(queue_cfg->port_name));

    list_add(&queue_cfg->queue_list_node, &current_worker->port_list);
}

static void rx_queue_ids_handler(vector_t tokens)
{
    int ii, qid;
    char *str;
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);
    struct queue_conf_stream *current_port = list_entry(current_worker->port_list.next,
            struct queue_conf_stream, queue_list_node);

    for (ii = 0; ii < VECTOR_SIZE(tokens) - 1; ii++) {
        str = VECTOR_SLOT(tokens, ii + 1);
        qid = atoi(str);
        if (qid < 0 || qid >= NETIF_MAX_QUEUES) {
            RTE_LOG(WARNING, NETIF, "invalid worker %s:%s rx_queue_id %s, using "
                    "default 0\n", current_worker->name, current_port->port_name, str);
            current_port->rx_queues[ii] = 0; /* using default worker config array */
        } else {
            RTE_LOG(WARNING, NETIF, "worker %s:%s rx_queue_id += %d\n",
                    current_worker->name, current_port->port_name, qid);
            current_port->rx_queues[ii] = qid;
        }
    }

    for ( ; ii < NETIF_MAX_QUEUES; ii++) /* unused space */
        current_port->rx_queues[ii] = NETIF_MAX_QUEUES;
}

static void tx_queue_ids_handler(vector_t tokens)
{
    int ii, qid;
    char *str;
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);
    struct queue_conf_stream *current_port = list_entry(current_worker->port_list.next,
            struct queue_conf_stream, queue_list_node);

    for (ii = 0; ii < VECTOR_SIZE(tokens) - 1; ii++) {
        str = VECTOR_SLOT(tokens, ii + 1);
        qid = atoi(str);
        if (qid < 0 || qid >= NETIF_MAX_QUEUES) {
            RTE_LOG(WARNING, NETIF, "invalid worker %s:%s tx_queue_id %s, uisng "
                    "default 0\n", current_worker->name, current_port->port_name, str);
            current_port->tx_queues[ii] = 0; /* using default worker config array */
        } else {
            RTE_LOG(WARNING, NETIF, "worker %s:%s tx_queue_id += %d\n",
                    current_worker->name, current_port->port_name, qid);
            current_port->tx_queues[ii] = qid;
        }
    }

    for ( ; ii < NETIF_MAX_QUEUES; ii++) /* unused space */
        current_port->tx_queues[ii] = NETIF_MAX_QUEUES;
}

static void isol_rx_cpu_ids_handler(vector_t tokens)
{
    int ii, cid;
    char *str = set_value(tokens);
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);
    struct queue_conf_stream *current_port = list_entry(current_worker->port_list.next,
            struct queue_conf_stream, queue_list_node);

    for (ii = 0; ii < VECTOR_SIZE(tokens) - 1; ii++) {
        str = VECTOR_SLOT(tokens, ii + 1);
        cid = atoi(str);
        if (cid <= 0 || cid >= DPVS_MAX_LCORE) {
            RTE_LOG(WARNING, NETIF, "invalid worker %s:%s:isol_rx_cpu_ids[%d] %s\n",
                    current_worker->name, current_port->port_name, ii, str);
            current_port->isol_rxq_lcore_ids[ii] = NETIF_LCORE_ID_INVALID;
        } else {
            RTE_LOG(INFO, NETIF, "worker %s:%s:isol_rx_cpu_ids[%d] = %d\n",
                    current_worker->name, current_port->port_name, ii, cid);
            current_port->isol_rxq_lcore_ids[ii] = cid;
        }
    }
}

static void isol_rxq_ring_sz_handler(vector_t tokens)
{
    int isol_rxq_ring_sz;
    char *str = set_value(tokens);
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);
    struct queue_conf_stream *current_port = list_entry(current_worker->port_list.next,
            struct queue_conf_stream, queue_list_node);

    assert(str);
    if (strspn(str, "0123456789") != strlen(str)) {
        RTE_LOG(WARNING, NETIF, "invalid worker %s:%s:isol_rxq_ring_sz %s,"
                " using default %d\n", current_worker->name, current_port->port_name,
                str, NETIF_ISOL_RXQ_RING_SZ_DEF);
        current_port->isol_rxq_ring_sz = NETIF_ISOL_RXQ_RING_SZ_DEF;
    } else {
        isol_rxq_ring_sz = atoi(str);
        RTE_LOG(INFO, NETIF, "worker %s:%s:isol_rxq_ring_sz = %d\n",
                current_worker->name, current_port->port_name, isol_rxq_ring_sz);
        current_port->isol_rxq_ring_sz = isol_rxq_ring_sz;
    }

    FREE_PTR(str);
}

void netif_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        netif_pktpool_nb_mbuf = NETIF_PKTPOOL_NB_MBUF_DEF;
        netif_pktpool_mbuf_cache = NETIF_PKTPOOL_MBUF_CACHE_DEF;
#ifdef CONFIG_DPVS_FDIR
        g_fdir_mode = RTE_FDIR_MODE_PERFECT;
#endif
    }
    /* KW_TYPE_NORMAL keyword */
}

void install_netif_keywords(void)
{
    install_keyword_root("netif_defs", netif_defs_handler);
    install_keyword("pktpool_size", pktpool_size_handler, KW_TYPE_INIT);
    install_keyword("pktpool_cache", pktpool_cache_handler, KW_TYPE_INIT);
#ifdef CONFIG_DPVS_FDIR
    install_keyword("fdir_mode", fdir_mode_handler, KW_TYPE_INIT);
#endif
    install_keyword("device", device_handler, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("rx", NULL, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("queue_number", rx_queue_number_handler, KW_TYPE_INIT);
    install_keyword("descriptor_number", rx_desc_nb_handler, KW_TYPE_INIT);
    install_keyword("rss", rss_handler, KW_TYPE_INIT);
    install_sublevel_end();
    install_keyword("tx", NULL, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("queue_number", tx_queue_number_handler, KW_TYPE_INIT);
    install_keyword("descriptor_number", tx_desc_nb_handler, KW_TYPE_INIT);
    install_sublevel_end();
    install_keyword("promisc_mode", promisc_mode_handler, KW_TYPE_INIT);
    install_keyword("allmulticast", allmulticast_handler, KW_TYPE_INIT);
    install_keyword("mtu", custom_mtu_handler,KW_TYPE_INIT);
    install_keyword("kni_name", kni_name_handler, KW_TYPE_INIT);
    install_sublevel_end();
    install_keyword("bonding", bonding_handler, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("mode", bonding_mode_handler, KW_TYPE_INIT);
    install_keyword("slave", bonding_slave_handler, KW_TYPE_INIT);
    install_keyword("primary", bonding_primary_handler, KW_TYPE_INIT);
    install_keyword("numa_node", bonding_numa_node_handler, KW_TYPE_INIT);
    install_keyword("kni_name", bonding_kni_name_handler, KW_TYPE_INIT);
    install_keyword("options", bonding_options_handler, KW_TYPE_INIT);
    install_sublevel_end();

    install_keyword_root("worker_defs", worker_defs_handler);
    install_keyword("worker", worker_handler, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("type", worker_type_handler, KW_TYPE_INIT);
    install_keyword("cpu_id", cpu_id_handler, KW_TYPE_INIT);
#ifdef CONFIG_ICMP_REDIRECT_CORE
    install_keyword("icmp_redirect_core", cpu_icmp_redirect_handler, KW_TYPE_INIT);
#endif
    install_keyword("port", worker_port_handler, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("rx_queue_ids", rx_queue_ids_handler, KW_TYPE_INIT);
    install_keyword("tx_queue_ids", tx_queue_ids_handler, KW_TYPE_INIT);
    install_keyword("isol_rx_cpu_ids", isol_rx_cpu_ids_handler, KW_TYPE_INIT);
    install_keyword("isol_rxq_ring_sz", isol_rxq_ring_sz_handler, KW_TYPE_INIT);
    install_sublevel_end();
    install_sublevel_end();
}

void netif_cfgfile_init(void)
{
    INIT_LIST_HEAD(&port_list);
    INIT_LIST_HEAD(&bond_list);
    INIT_LIST_HEAD(&worker_list);
}

static void netif_cfgfile_term(void)
{
    struct port_conf_stream *port_cfg, *port_cfg_next;
    struct bond_conf_stream *bond_cfg, *bond_cfg_next;
    struct worker_conf_stream *worker_cfg, *worker_cfg_next;
    struct queue_conf_stream *queue_cfg, *queue_cfg_next;

    list_for_each_entry_safe(port_cfg, port_cfg_next, &port_list, port_list_node) {
        list_del(&port_cfg->port_list_node);
        rte_free(port_cfg);
    }

    list_for_each_entry_safe(bond_cfg, bond_cfg_next, &bond_list, bond_list_node) {
        list_del(&bond_cfg->bond_list_node);
        rte_free(bond_cfg);
    }

    list_for_each_entry_safe(worker_cfg, worker_cfg_next, &worker_list,
            worker_list_node) {
        list_del(&worker_cfg->worker_list_node);
        list_for_each_entry_safe(queue_cfg, queue_cfg_next, &worker_cfg->port_list,
                queue_list_node) {
            list_del(&queue_cfg->queue_list_node);
            rte_free(queue_cfg);
        }
        rte_free(worker_cfg);
    }
}


#ifdef CONFIG_DPVS_NETIF_DEBUG
#include <arpa/inet.h>
#include <netinet/in.h>

static inline int parse_ether_hdr(struct rte_mbuf *mbuf, uint16_t port, uint16_t queue) {
    struct rte_ether_hdr *eth_hdr;
    char saddr[18], daddr[18];
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_ether_format_addr(saddr, sizeof(saddr), &eth_hdr->s_addr);
    rte_ether_format_addr(daddr, sizeof(daddr), &eth_hdr->d_addr);
    RTE_LOG(INFO, NETIF, "[%s] lcore=%u port=%u queue=%u ethtype=%0x saddr=%s daddr=%s\n",
            __func__, rte_lcore_id(), port, queue, rte_be_to_cpu_16(eth_hdr->ether_type),
            saddr, daddr);
    return EDPVS_OK;
}

static inline int is_ipv4_pkt_valid(struct rte_ipv4_hdr *iph, uint32_t link_len)
{
    if (((iph->version_ihl) >> 4) != 4)
        return EDPVS_INVAL;
    if ((iph->version_ihl & 0xf) < 5)
        return EDPVS_INVAL;
    if (rte_cpu_to_be_16(iph->total_length) < sizeof(struct rte_ipv4_hdr))
        return EDPVS_INVAL;
    return EDPVS_OK;
}

__rte_unused static void parse_ipv4_hdr(struct rte_mbuf *mbuf, uint16_t port, uint16_t queue)
{
    char saddr[16], daddr[16];
    uint16_t lcore;
    struct rte_ipv4_hdr *iph;
    struct rte_udp_hdr *uh;

    iph = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    if (is_ipv4_pkt_valid(iph, mbuf->pkt_len) < 0)
        return;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) +
            (RTE_IPV4_HDR_IHL_MASK & iph->version_ihl) * sizeof(uint32_t));

    lcore = rte_lcore_id();
    if (!inet_ntop(AF_INET, &iph->src_addr, saddr, sizeof(saddr)))
        return;
    if (!inet_ntop(AF_INET, &iph->dst_addr, daddr, sizeof(daddr)))
        return;

    RTE_LOG(INFO, NETIF, "[%s] lcore=%u port=%u queue=%u ipv4_hl=%u tos=%u tot=%u "
            "id=%u ttl=%u prot=%u src=%s dst=%s sport=%04x|%u dport=%04x|%u\n",
            __func__, lcore, port, queue, RTE_IPV4_HDR_IHL_MASK & iph->version_ihl,
            iph->type_of_service, ntohs(iph->total_length),
            ntohs(iph->packet_id), iph->time_to_live, iph->next_proto_id, saddr, daddr,
            uh->src_port, ntohs(uh->src_port), uh->dst_port, ntohs(uh->dst_port));
    return;
}

__rte_unused static void pkt_send_back(struct rte_mbuf *mbuf, struct netif_port *port)
{
    struct rte_ether_hdr *ehdr;
    struct rte_ether_addr eaddr;
    ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    rte_ether_addr_copy(&ehdr->s_addr, &eaddr);
    rte_ether_addr_copy(&ehdr->d_addr, &ehdr->s_addr);
    rte_ether_addr_copy(&eaddr, &ehdr->d_addr);
    netif_xmit(mbuf, port);
}
#endif

/********************************************* mbufpool *******************************************/
struct rte_mempool *pktmbuf_pool[DPVS_MAX_SOCKET];

static inline void netif_pktmbuf_pool_init(void)
{
    int i;
    char poolname[32];
    for (i = 0; i < get_numa_nodes(); i++) {
        snprintf(poolname, sizeof(poolname), "mbuf_pool_%d", i);
        pktmbuf_pool[i] = rte_pktmbuf_pool_create(poolname, netif_pktpool_nb_mbuf,
                netif_pktpool_mbuf_cache, 0, RTE_MBUF_DEFAULT_BUF_SIZE, i);
        if (!pktmbuf_pool[i])
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d", i);
    }
}

/******************************************* pkt-type *********************************************/
#define NETIF_PKT_TYPE_TABLE_BITS 8
#define NETIF_PKT_TYPE_TABLE_BUCKETS (1 << NETIF_PKT_TYPE_TABLE_BITS)
#define NETIF_PKT_TYPE_TABLE_MASK (NETIF_PKT_TYPE_TABLE_BUCKETS - 1)
/* Note: Lockless. pkt_type can only be registered on initialization stage,
 *       and unregistered on cleanup stage. Otherwise uncertain behavior may arise.
 */
static struct list_head pkt_type_tab[NETIF_PKT_TYPE_TABLE_BUCKETS];

static inline int pkt_type_tab_hashkey(uint16_t type)
{
    return type & NETIF_PKT_TYPE_TABLE_MASK;
}

static inline void netif_pkt_type_tab_init(void)
{
    int i;
    for (i = 0; i < NETIF_PKT_TYPE_TABLE_BUCKETS; i++)
        INIT_LIST_HEAD(&pkt_type_tab[i]);
}

int netif_register_pkt(struct pkt_type *pt)
{
    struct pkt_type *cur;
    int hash;
    if (unlikely(NULL == pt))
        return EDPVS_INVAL;

    hash = pkt_type_tab_hashkey(pt->type);
    list_for_each_entry(cur, &pkt_type_tab[hash], list) {
        if (cur->type == pt->type) {
            return EDPVS_EXIST;
        }
    }
    list_add_tail(&pt->list, &pkt_type_tab[hash]);
    return EDPVS_OK;
}

int netif_unregister_pkt(struct pkt_type *pt)
{
    struct pkt_type *cur;
    int hash;
    if (unlikely(NULL == pt))
        return EDPVS_INVAL;

    hash = pkt_type_tab_hashkey(pt->type);
    list_for_each_entry(cur, &pkt_type_tab[hash], list) {
        if (cur->type == pt->type) {
            list_del_init(&pt->list);
            return EDPVS_OK;
        }
    }
    return EDPVS_NOTEXIST;
}

static struct pkt_type *pkt_type_get(__be16 type, struct netif_port *port)
{
    struct pkt_type *pt;
    int hash;

    hash = pkt_type_tab_hashkey(type);
    list_for_each_entry(pt, &pkt_type_tab[hash], list) {
        if (pt->type == type && ((pt->port == NULL) || pt->port == port)) {
            return pt;
        }
    }
    return NULL;
}

/****************************************** lcore  conf ********************************************/
/* per-lcore statistics */
static struct netif_lcore_stats lcore_stats[DPVS_MAX_LCORE];
/* per-lcore isolated reception queues */
static struct list_head isol_rxq_tab[DPVS_MAX_LCORE];

/* worker configuration array */
static struct netif_lcore_conf lcore_conf[DPVS_MAX_LCORE + 1];

/* Note: Lockless, lcore_conf is set on initialization stage by cfgfile /etc/dpvs.conf.
config sample:
static struct netif_lcore_conf lcore_conf[DPVS_MAX_LCORE + 1] = {
    {.id = 1, .nports = 2, .pqs = {
        {.id = 0, .nrxq = 1, .ntxq = 1, .rxqs = {{.id = 0, }, }, .txqs = {{.id = 0, }, }, },
        {.id = 1, .nrxq = 0, .ntxq = 1, .txqs = {{.id = 0, }, }, }, },
    },
    {.id = 2, .nports = 2, .pqs = {
        {.id = 0, .nrxq = 1, .ntxq = 1, .rxqs = {{.id = 1, }, }, .txqs = {{.id = 1, }, }, },
        {.id = 1, .nrxq = 1, .ntxq = 2, .rxqs = {{.id = 0, }, }, .txqs = {{.id = 1, }, {.id = 4, }}, }, },
    },
    {.id = 3, .nports = 2, .pqs = {
        {.id = 0, .nrxq = 2, .ntxq = 1, .rxqs = {{.id = 2, }, {.id = 3, }, }, .txqs = {{.id = 2, }, }, },
        {.id = 1, .nrxq = 1, .ntxq = 2, .rxqs = {{.id = 1, }, }, .txqs = {{.id = 2, }, {.id = 3, }, }, }, },
    },
};
*/

static int isol_rxq_add(lcoreid_t cid, portid_t pid, queueid_t qid,
        unsigned rb_sz, struct netif_queue_conf *rxq);
static void isol_rxq_del(struct rx_partner *isol_rxq, bool force);

static void config_lcores(struct list_head *worker_list)
{
    int ii, tk;
    int cpu_id_min, cpu_left, cpu_cnt;
    lcoreid_t id = 0;
    portid_t pid;
    struct netif_port *port;
    struct queue_conf_stream *queue;
    struct worker_conf_stream *worker, *worker_next, *worker_min;

    memset(lcore_conf, 0, sizeof(lcore_conf));

    cpu_cnt = cpu_left = list_elems(worker_list);
    list_for_each_entry_safe(worker, worker_next, worker_list, worker_list_node) {
        if (!strcmp(worker->type, "master")) {
            list_move_tail(&worker->worker_list_node, worker_list);
            cpu_left--;
        }
        if (--cpu_cnt == 0)
            break;
    }

    while (cpu_left > 0) {
        cpu_id_min = DPVS_MAX_LCORE;
        worker_min = NULL;

        tk = 0;
        list_for_each_entry(worker, worker_list, worker_list_node) {
            if (cpu_id_min > worker->cpu_id) {
                cpu_id_min = worker->cpu_id;
                worker_min = worker;
            }
            if (++tk >= cpu_left)
                break;
        }
        assert(worker_min != NULL);

        tk = 0;
        lcore_conf[id].id = worker_min->cpu_id;
        if (!strncmp(worker_min->type, "slave", sizeof("slave")))
            lcore_conf[id].type = LCORE_ROLE_FWD_WORKER;
        else if (!strncmp(worker_min->type, "kni", sizeof("kni")))
            lcore_conf[id].type = LCORE_ROLE_KNI_WORKER;
        else
            lcore_conf[id].type = LCORE_ROLE_IDLE;

        list_for_each_entry_reverse(queue, &worker_min->port_list, queue_list_node) {
            port = netif_port_get_by_name(queue->port_name);
            if (port)
                pid = port->id;
            else
                pid = NETIF_PORT_ID_INVALID;
            lcore_conf[id].pqs[tk].id = pid;

            for (ii = 0; queue->rx_queues[ii] != NETIF_MAX_QUEUES && ii < NETIF_MAX_QUEUES;
                 ii++) {
                lcore_conf[id].pqs[tk].rxqs[ii].id = queue->rx_queues[ii];
                if (queue->isol_rxq_lcore_ids[ii] != NETIF_LCORE_ID_INVALID) {
                    if (isol_rxq_add(queue->isol_rxq_lcore_ids[ii],
                                port->id, queue->rx_queues[ii],
                                queue->isol_rxq_ring_sz,
                                &lcore_conf[id].pqs[tk].rxqs[ii]) < 0) {
                        RTE_LOG(ERR, NETIF, "%s: isol_rxq add failed for cpu%d:%s:"
                                "rx%d, recieving locally instead.\n", __func__,
                                worker_min->cpu_id, port->name, queue->rx_queues[ii]);
                    } else {
                        RTE_LOG(INFO, NETIF, "%s: isol_rxq on cpu%d with ring size %d is "
                                "added for cpu%d:%s:rx%d\n", __func__,
                                queue->isol_rxq_lcore_ids[ii], queue->isol_rxq_ring_sz,
                                worker_min->cpu_id, port->name, queue->rx_queues[ii]);
                    }
                }
            }
            lcore_conf[id].pqs[tk].nrxq = ii;

            for (ii = 0; queue->tx_queues[ii] != NETIF_MAX_QUEUES && ii < NETIF_MAX_QUEUES;
                 ii++)
                lcore_conf[id].pqs[tk].txqs[ii].id = queue->tx_queues[ii];
            lcore_conf[id].pqs[tk].ntxq = ii;
            tk++;
        }
        lcore_conf[id].nports = tk;
        id++;

        list_move_tail(&worker_min->worker_list_node, worker_list);
        cpu_left--;
    }
}

/* fast searching tables */
lcoreid_t lcore2index[DPVS_MAX_LCORE+1];
portid_t port2index[DPVS_MAX_LCORE][NETIF_MAX_PORTS];

static int lcore_index_init(void)
{
    lcoreid_t cid;
    int i;

    for (i = 0; i <= DPVS_MAX_LCORE; i++)
        lcore2index[i] = DPVS_MAX_LCORE;

    for (i = 0; lcore_conf[i].nports > 0; i++) {
        cid = lcore_conf[i].id;
        if (!rte_lcore_is_enabled(cid))
            return EDPVS_NONEALCORE;
        lcore2index[cid] = i;
    }

#ifdef CONFIG_DPVS_NETIF_DEBUG
    printf("lcore fast searching table: \n");
    for (i = 0; i <= DPVS_MAX_LCORE; i++) {
        if (lcore2index[i] != DPVS_MAX_LCORE)
            printf("\tcid: %2d --> %2d\n", i, lcore2index[i]);
    }
#endif

    return EDPVS_OK;
}

static void port_index_init(void)
{
    int ii, jj, tk;
    lcoreid_t cid;
    portid_t pid;
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++)
        for (jj = 0; jj < NETIF_MAX_PORTS; jj++)
            port2index[ii][jj] = NETIF_PORT_ID_INVALID;

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        tk = 0;
        for (jj = 0; jj < lcore_conf[ii].nports; jj++) {
            cid = lcore_conf[ii].id;
            pid = lcore_conf[ii].pqs[jj].id;
            port2index[cid][pid] = tk++;
        }
    }
#ifdef CONFIG_DPVS_NETIF_DEBUG
    printf("port fast searching table(port2index[cid][pid]): \n");
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        for (jj = 0; jj < NETIF_MAX_PORTS; jj++) {
            if (port2index[ii][jj] != NETIF_PORT_ID_INVALID)
                printf("\tcid: %2d, pid: %2d --> index: %2d\n", ii, jj, port2index[ii][jj]);
        }
    }
#endif
}

void netif_get_slave_lcores(uint8_t *nb, uint64_t *mask)
{
    int i = 0;
    uint64_t slave_lcore_mask = 0L;
    uint8_t slave_lcore_nb = 0;

    while (lcore_conf[i].nports > 0) {
        /* LCORE_ROLE_KNI_WORKER should be excluded,
         * as ports is configured for KNI core. */
        if (lcore_conf[i].type == LCORE_ROLE_FWD_WORKER) {
            slave_lcore_nb++;
            slave_lcore_mask |= (1L << lcore_conf[i].id);
        }
        i++;
    }

    if (nb)
        *nb = slave_lcore_nb;
    if (mask)
        *mask = slave_lcore_mask;
}

static void netif_get_isol_rx_lcores(uint8_t *nb, uint64_t *mask)
{
    lcoreid_t cid;
    uint64_t isol_lcore_mask = 0L;
    uint8_t isol_lcore_nb = 0;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!list_empty(&isol_rxq_tab[cid])) {
            isol_lcore_nb++;
            isol_lcore_mask |= (1L << cid);
        }
    }

    if (nb)
        *nb = isol_lcore_nb;
    if (mask)
        *mask = isol_lcore_mask;
}

static void build_lcore_index(void)
{
    int cid, idx = 0;

    g_lcore_index2id[idx++] = rte_get_main_lcore();

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++)
        if (g_lcore_role[cid] == LCORE_ROLE_FWD_WORKER)
            g_lcore_index2id[idx++] = cid;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++)
        if (g_lcore_role[cid] == LCORE_ROLE_ISOLRX_WORKER)
            g_lcore_index2id[idx++] = cid;
    g_lcore_num = idx;

    for (idx = 0; idx < DPVS_MAX_LCORE; idx++) {
        cid = g_lcore_index2id[idx];
        if (cid >= 0 && cid < DPVS_MAX_LCORE)
            g_lcore_id2index[cid] = idx;
    }
}

static inline void dump_lcore_role(void)
{
    dpvs_lcore_role_t role;
    lcoreid_t cid;
    char bufs[LCORE_ROLE_MAX+1][1024];
    char results[sizeof bufs];

    for (role = 0; role < LCORE_ROLE_MAX; role++)
        snprintf(bufs[role], sizeof(bufs[role]), "\t%s: ",
                dpvs_lcore_role_str(role));

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        role = g_lcore_role[cid];
        snprintf(&bufs[role][strlen(bufs[role])], sizeof(bufs[role])
                    - strlen(bufs[role]), "%-4d", cid);
    }

    snprintf(results, sizeof(results), "%s", bufs[0]);
    for (role = 1; role < LCORE_ROLE_MAX; role++) {
        strncat(results, "\n", sizeof(results) - strlen(results) - 1);
        strncat(results, bufs[role], sizeof(results) - strlen(results) - 1);
    }

    RTE_LOG(INFO, NETIF, "LCORE ROLES:\n%s\n", results);
}

static void lcore_role_init(void)
{
    int i, cid;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++)
        if (!rte_lcore_is_enabled(cid))
            /* invalidate the disabled cores */
            g_lcore_role[cid] = LCORE_ROLE_MAX;

    cid = rte_get_main_lcore();

    assert(g_lcore_role[cid] == LCORE_ROLE_IDLE);
    g_lcore_role[cid] = LCORE_ROLE_MASTER;

    i = 0;
    while (lcore_conf[i].nports > 0) {
        cid = lcore_conf[i].id;
        assert(g_lcore_role[cid] == LCORE_ROLE_IDLE);
        g_lcore_role[cid] = lcore_conf[i].type;
        i++;
    }

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!list_empty(&isol_rxq_tab[cid])) {
            assert(g_lcore_role[cid] == LCORE_ROLE_IDLE);
            g_lcore_role[cid] =  LCORE_ROLE_ISOLRX_WORKER;
        }
    }

    build_lcore_index();
    dump_lcore_role();
}

static inline void netif_copy_lcore_stats(struct netif_lcore_stats *stats)
{
    lcoreid_t cid;
    cid = rte_lcore_id();
    assert(cid < DPVS_MAX_LCORE);
    rte_memcpy(stats, &lcore_stats[cid], sizeof(struct netif_lcore_stats));
}

static int port_rx_queues_get(portid_t pid)
{
    int i = 0, j;
    int rx_ports = 0;

    while (lcore_conf[i].nports > 0) {
        for (j = 0;  j < lcore_conf[i].nports; j++) {
            if (lcore_conf[i].pqs[j].id == pid)
                rx_ports += lcore_conf[i].pqs[j].nrxq;
        }
        i++;
    }
    return rx_ports;
}

static int port_tx_queues_get(portid_t pid)
{
    int i = 0, j;
    int tx_ports = 0;

    while (lcore_conf[i].nports > 0) {
        for (j = 0;  j < lcore_conf[i].nports; j++) {
            if (lcore_conf[i].pqs[j].id == pid)
                tx_ports += lcore_conf[i].pqs[j].ntxq;
        }
        i++;
    }
    return tx_ports;
}

/*
 * params:
 *   @pid: [in] port id
 *   @qids: [out] queue id array containing rss queues when return
 *   @n_queues: [in,out], `qids` array length when input, rss queue number when return
 */
static int get_configured_rss_queues(portid_t pid, queueid_t *qids, int *n_queues)
{
    int i, j, k, tk = 0;
    if (!qids || !n_queues || *n_queues < NETIF_MAX_QUEUES)
        return EDPVS_INVAL;

    for (i = 0; lcore_conf[i].nports > 0; i++) {
        if (lcore_conf[i].type != LCORE_ROLE_FWD_WORKER)
            continue;
        for (j = 0; j < lcore_conf[i].nports; j++) {
            if (lcore_conf[i].pqs[j].id == pid)
                break;
        }
        if (lcore_conf[i].pqs[j].id != pid)
            return EDPVS_INVAL;
        for (k = 0; k < lcore_conf[i].pqs[j].nrxq; k++) {
            qids[tk++] = lcore_conf[i].pqs[j].txqs[k].id;
            if (tk > *n_queues)
                return EDPVS_NOMEM;
        }
    }
    *n_queues = tk;
    return EDPVS_OK;
}

static uint8_t get_configured_port_nb(int lcores, const struct netif_lcore_conf *lcore_conf)
{
    int i = 0, j, k;
    uint8_t ports_nb = 0;
    bool is_exist;
    portid_t pid, ports_array[NETIF_MAX_PORTS];

    while (lcore_conf[i].nports > 0 && i < lcores) {
        for (j = 0; j < lcore_conf[i].nports; j++) {
            pid = lcore_conf[i].pqs[j].id;
            is_exist = false;
            for (k = 0; k < ports_nb; k++) {
                if (ports_array[k] == pid) {
                    is_exist = true;
                    break;
                }
            }
            if (!is_exist)
                ports_array[ports_nb++] = pid;
        }
        i++;
    }
    return ports_nb;
}

#define LCONFCHK_MARK                       255
#define LCONFCHK_OK                         0
#define LCONFCHK_REPEATED_RX_QUEUE_ID       -2
#define LCONFCHK_REPEATED_TX_QUEUE_ID       -3
#define LCONFCHK_DISCONTINUOUS_QUEUE_ID     -4
#define LCONFCHK_PORT_NOT_ENOUGH            -5
#define LCONFCHK_INCORRECT_TX_QUEUE_NUM     -6
#define LCONFCHK_NO_SLAVE_LCORES            -7

static int check_lcore_conf(int lcores, const struct netif_lcore_conf *lcore_conf)
{
    int i = 0, j, k;
    uint8_t nports, nqueues;
    uint8_t nports_conf = get_configured_port_nb(lcores, lcore_conf);
    portid_t pid;
    queueid_t qid;
    struct netif_lcore_conf mark;
    memset(&mark, 0, sizeof(mark));
    nports = dpvs_rte_eth_dev_count();
    while (lcore_conf[i].nports > 0)
    {
        if (lcore_conf[i].nports > nports)
            return LCONFCHK_PORT_NOT_ENOUGH;
        for (j = 0; j < lcore_conf[i].nports; j++) {
            pid = lcore_conf[i].pqs[j].id;
            for (k = 0; k < lcore_conf[i].pqs[j].nrxq; k++) {
                qid = lcore_conf[i].pqs[j].rxqs[k].id;
                if (LCONFCHK_MARK == mark.pqs[pid].rxqs[qid].id) {
                    RTE_LOG(ERR, NETIF, "rx qid: %d for cid: %d is already used.",
                            qid, lcore_conf[i].id);
                    return LCONFCHK_REPEATED_RX_QUEUE_ID;
                } else
                    mark.pqs[pid].rxqs[qid].id = LCONFCHK_MARK;
            }
            for (k = 0; k <lcore_conf[i].pqs[j].ntxq; k++) {
                qid = lcore_conf[i].pqs[j].txqs[k].id;
                if (LCONFCHK_MARK == mark.pqs[pid].txqs[qid].id) {
                    RTE_LOG(ERR, NETIF, "tx qid: %d for cid: %d is already used.",
                            qid, lcore_conf[i].id);
                    return LCONFCHK_REPEATED_TX_QUEUE_ID;
                } else
                    mark.pqs[pid].txqs[qid].id = LCONFCHK_MARK;
            }
        }
        if (++i >= lcores)
            break;
    }
    if (i == 0)
        return LCONFCHK_NO_SLAVE_LCORES;

    for (i = 0; i < nports; i++) {
        nqueues = port_rx_queues_get(i);
        for (j = 0; j < nqueues; j++) {
            //printf("[dpdk%d:rx%d] %d    ", i, j, mark.pqs[i].rxqs[j].id);
            if (LCONFCHK_MARK != mark.pqs[i].rxqs[j].id) {
                return LCONFCHK_DISCONTINUOUS_QUEUE_ID;
            }
        }
        nqueues = port_tx_queues_get(i);
        for (j = 0; j < nqueues; j++) {
            //printf("[dpdk%d:tx%d] %d    ", i, j, mark.pqs[i].txqs[j].id);
            if (LCONFCHK_MARK != mark.pqs[i].txqs[j].id) {
                return LCONFCHK_DISCONTINUOUS_QUEUE_ID;
            }
        }
    }

    i = 0;
    while (lcore_conf[i].nports > 0) {
        if (lcore_conf[i].nports != nports_conf)
            return LCONFCHK_INCORRECT_TX_QUEUE_NUM;
        for (j = 0; j < lcore_conf[i].nports; j++)
            if (lcore_conf[i].pqs[j].ntxq < 1)
                return LCONFCHK_INCORRECT_TX_QUEUE_NUM;
        if (++i >= lcores)
            break;
    }
    return LCONFCHK_OK;
}

static inline void lcore_stats_burst(struct netif_lcore_stats *stats,
                                     size_t len)
{
    stats->pktburst++;

    if (0 == len) {
        stats->zpktburst++;
        stats->z2hpktburst++;
    } else if (len <= NETIF_MAX_PKT_BURST/2) {
        stats->z2hpktburst++;
    } else if (len < NETIF_MAX_PKT_BURST) {
        stats->h2fpktburst++;
    } else {
        stats->h2fpktburst++;
        stats->fpktburst++;
    }
}

static inline void isol_rxq_init(void)
{
    int i;
    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        INIT_LIST_HEAD(&isol_rxq_tab[i]);
    }
}

/* call me at initialization before lcore loop */
static int isol_rxq_add(lcoreid_t cid, portid_t pid, queueid_t qid,
                        unsigned rb_sz, struct netif_queue_conf *rxq)
{
    assert(cid <= DPVS_MAX_LCORE);
    int rb_sz_r;
    struct rx_partner *isol_rxq;
    struct rte_ring *rb;
    char name[32];

    isol_rxq = rte_zmalloc("isol_rxq", sizeof(struct rx_partner), 0);
    if (unlikely(!isol_rxq))
        return EDPVS_NOMEM;

    is_power2(rb_sz, 0, &rb_sz_r);
    memset(name, 0, 32);
    snprintf(name, sizeof(name) - 1, "isol_rxq_c%dp%dq%d", cid, pid, qid);

    rb = rte_ring_create(name, rb_sz_r, rte_socket_id(),
            RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (unlikely(!rb))
        return EDPVS_DPDKAPIFAIL;

    isol_rxq->cid = cid;
    isol_rxq->pid = pid;
    isol_rxq->qid = qid;
    isol_rxq->rxq = rxq;
    isol_rxq->rb = rb;

    list_add(&isol_rxq->lnode, &isol_rxq_tab[cid]);
    rxq->isol_rxq = isol_rxq;

    return EDPVS_OK;
}

/* call me at termination */
__rte_unused
static void isol_rxq_del(struct rx_partner *isol_rxq, bool force)
{
    assert(isol_rxq);

    /* stop recieving packets */
    list_del(&isol_rxq->lnode);

    if (force) {
        /* dequeue all packets in the ring and drop them */
        struct rte_mbuf *mbuf;
        while (!rte_ring_dequeue(isol_rxq->rb, (void **)&mbuf))
            rte_pktmbuf_free(mbuf);
    } else {
        /* wait until all packets in the ring processed */
        while (!rte_ring_empty(isol_rxq->rb))
            ;
    }

    /* remove isolate cpu packet reception */
    isol_rxq->rxq->isol_rxq = NULL;

    rte_ring_free(isol_rxq->rb);
    rte_free(isol_rxq);

    isol_rxq = NULL;
}

inline static void recv_on_isol_lcore(void *dump)
{
    struct rx_partner *isol_rxq;
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    unsigned int rx_len, qspc;
    int i, res;
    lcoreid_t cid = rte_lcore_id();

    list_for_each_entry(isol_rxq, &isol_rxq_tab[cid], lnode) {
        assert(isol_rxq->cid == cid);
again:
        rx_len = rte_eth_rx_burst(isol_rxq->pid, isol_rxq->qid,
                mbufs, NETIF_MAX_PKT_BURST);
        /* It is safe to reuse lcore_stats for isolate recieving. Isolate recieving
         * always lays on different lcores from packet processing. */
        lcore_stats_burst(&lcore_stats[cid], rx_len);

        if (rx_len == 0)
            continue;

        lcore_stats[cid].ipackets += rx_len;
        for (i = 0; i < rx_len; i++)
            lcore_stats[cid].ibytes += mbufs[i]->pkt_len;

        res = rte_ring_enqueue_bulk(isol_rxq->rb, (void *const * )mbufs, rx_len, &qspc);
        if (res < rx_len) {
            RTE_LOG(WARNING, NETIF, "%s [%d]: %d packets failed to enqueue,"
                    " space avail: %u\n", __func__, cid, rx_len - res, qspc);
            lcore_stats[cid].dropped += (rx_len - res);
            for (i = res; i < rx_len; i++)
                rte_pktmbuf_free(mbufs[i]);
        }

        if (rx_len >= NETIF_MAX_PKT_BURST && rte_ring_free_count(isol_rxq->rb) >= NETIF_MAX_PKT_BURST)
            goto again;
    }
}

inline static bool is_isol_rxq_lcore(lcoreid_t cid)
{
    assert(cid < DPVS_MAX_LCORE);

    return !list_empty(&isol_rxq_tab[cid]);
}

inline static bool is_kni_lcore(lcoreid_t cid)
{
    assert(cid < DPVS_MAX_LCORE);

    return g_kni_lcore_id == cid;
}

bool netif_lcore_is_fwd_worker(lcoreid_t cid)
{
    if (cid > DPVS_MAX_LCORE)
        return false;

    return (lcore_conf[lcore2index[cid]].type  ==
            LCORE_ROLE_FWD_WORKER) ? true : false;
}

static inline uint16_t netif_rx_burst(portid_t pid, struct netif_queue_conf *qconf)
{
    struct rte_mbuf *mbuf;
    int nrx = 0;

    if (qconf->isol_rxq) {
        /* note API rte_ring_dequeue_bulk of dpdk-16.07 is not suitable, replace with
         * its bulk version after upgrading to new dpdk version */
        while (0 == rte_ring_dequeue(qconf->isol_rxq->rb, (void**)&mbuf)) {
            qconf->mbufs[nrx++] = mbuf;
            if (unlikely(nrx >= NETIF_MAX_PKT_BURST))
                break;
        }

        /* Shoul we integrate statistics of isolated recieve lcore into packet
         * processing lcore ? No! we just leave the work to tools */
    } else {
        nrx = rte_eth_rx_burst(pid, qconf->id, qconf->mbufs, NETIF_MAX_PKT_BURST);
    }

    qconf->len = nrx;
    return nrx;
}

/* just for print */
struct port_queue_lcore_map {
    portid_t pid;
    char mac_addr[18];
    queueid_t rx_qid[NETIF_MAX_QUEUES];
    queueid_t tx_qid[NETIF_MAX_QUEUES];
};
portid_t netif_max_pid;
queueid_t netif_max_qid;
struct port_queue_lcore_map pql_map[NETIF_MAX_PORTS];

static int build_port_queue_lcore_map(void)
{
    int i, j, k;
    lcoreid_t cid;
    portid_t pid;
    queueid_t qid;
    int bflag = 0;
    struct netif_port *dev;

    /* init map struct */
    for (i = 0; i < NETIF_MAX_PORTS; i++) {
        pql_map[i].pid = NETIF_PORT_ID_INVALID;
        snprintf(&pql_map[i].mac_addr[0], 18, "xx:xx:xx:xx:xx:xx");
        for (j = 0; j < NETIF_MAX_QUEUES; j++) {
            pql_map[i].rx_qid[j] = NETIF_PORT_ID_INVALID;
            pql_map[i].tx_qid[j] = NETIF_PORT_ID_INVALID;
        }
    }

    /* fill in map struct */
    i = 0;
    while (lcore_conf[i].nports > 0) {
        cid = lcore_conf[i].id;
        for (j = 0; j < lcore_conf[i].nports; j++) {
            pid = lcore_conf[i].pqs[j].id;
            if (pid > netif_max_pid)
                netif_max_pid = pid;
            if (pql_map[pid].pid == NETIF_PORT_ID_INVALID) {
                pql_map[pid].pid = pid;

                dev = netif_port_get(pid);
                if (dev) {
                    rte_ether_format_addr(pql_map[pid].mac_addr,
                            sizeof(pql_map[pid].mac_addr), &dev->addr);
                }
            }
            else if (pql_map[pid].pid != pid) {
                RTE_LOG(ERR, NETIF, "%s: port id not consistent\n", __func__);
                bflag = 1;
                break;
            }
            for (k = 0; k < lcore_conf[i].pqs[j].nrxq; k++) {
                qid = lcore_conf[i].pqs[j].rxqs[k].id;
                if (qid > netif_max_qid)
                    netif_max_qid = qid;
                pql_map[pid].rx_qid[qid] = cid;
            }
            for (k = 0; k < lcore_conf[i].pqs[j].ntxq; k++) {
                qid = lcore_conf[i].pqs[j].txqs[k].id;
                if (qid > netif_max_qid)
                    netif_max_qid = qid;
                pql_map[pid].tx_qid[qid] = cid;
            }
        }
        if (bflag)
            break;
        i++;
    }
    return EDPVS_OK;
}

int netif_print_lcore_conf(char *buf, int *len, bool is_all, portid_t pid)
{
    int i, j;
    char tbuf[256], tbuf2[256], line[1024];
    char rxbuf[16], txbuf[16];
    int left_len;
    struct netif_port *port;

    /* format map in string */
    memset(buf, 0, *len);
    if (is_all) {
        snprintf(line, sizeof(line) - 1, "    %-12s", "");
        for (i = 0; i <= netif_max_pid; i++) {
            port = netif_port_get(i);
            assert(port);
            snprintf(tbuf2, sizeof(tbuf2) - 1, "%s: %s ", port->name, pql_map[i].mac_addr);
            snprintf(tbuf, sizeof(tbuf) - 1, "%-25s", tbuf2);
            strncat(line, tbuf, sizeof(line) - strlen(line) - 1);
        }
        strncat(line, "\n", sizeof(line) - strlen(line) - 1);
        left_len = *len - strlen(buf);
        if (unlikely(left_len < 0)) {
            RTE_LOG(WARNING, NETIF, "buffer not enough for '%s'\n", __func__);
            *len = strlen(buf);
            return EDPVS_INVAL;
        }
        strncat(buf, line, left_len - 1);
    }

    for (i = 0; i <= netif_max_qid; i++) {
        snprintf(tbuf2, sizeof(tbuf2) - 1, "rx%d-tx%d", i, i);
        snprintf(line, sizeof(line) - 1, "    %-12s", tbuf2);
        for (j = 0; j <= netif_max_pid; j++) {
            if (!is_all && pid != j)
                continue;
            if (NETIF_PORT_ID_INVALID == pql_map[j].rx_qid[i])
                snprintf(rxbuf, sizeof(rxbuf) - 1, "xx");
            else
                snprintf(rxbuf, sizeof(rxbuf) - 1, "cpu%d", pql_map[j].rx_qid[i]);
            if (NETIF_PORT_ID_INVALID == pql_map[j].tx_qid[i])
                snprintf(txbuf, sizeof(txbuf) - 1, "xx");
            else
                snprintf(txbuf, sizeof(txbuf) - 1, "cpu%d", pql_map[j].tx_qid[i]);

            snprintf(tbuf2, sizeof(tbuf2) - 1, "%s-%s", rxbuf, txbuf);
            snprintf(tbuf, sizeof(tbuf) - 1, "%-25s", tbuf2);
            strncat(line, tbuf, sizeof(line) - strlen(line) - 1);
        }
        strncat(line, "\n", sizeof(line) - strlen(line) - 1);
        left_len = *len - strlen(buf);
        if (unlikely(left_len <= 0)) {
            RTE_LOG(WARNING, NETIF, "buffer not enough for '%s'\n", __func__);
            *len = strlen(buf);
            return EDPVS_INVAL;
        }
        strncat(buf, line, left_len - 1);
    }

    *len = strlen(buf);
    return EDPVS_OK;
}

int netif_print_port_queue_conf(portid_t pid, char *buf, int *len)
{
    int i, j;
    char line[1024], tbuf[32], tbuf2[32];
    struct port_queue_lcore_map *pmap = NULL;
    int left_len;

    if (unlikely(!buf || !len || *len <= 0))
        return EDPVS_INVAL;

    for (i = 0; i <= netif_max_pid; i++) {
        if (pql_map[i].pid == pid) {
            pmap = &pql_map[i];
            break;
        }
    }
    if (!pmap) {
        RTE_LOG(WARNING, NETIF, "[%s] no queue confiugred on dpdk%d\n", __func__, pid);
        return EDPVS_NOTEXIST;
    }

    memset(buf, 0, *len);
    snprintf(buf, *len, "configured queues on dpdk%d (%s):\n    %-12s%-12s%-12s\n",
            pmap->pid, pmap->mac_addr, "QUEUE", "RX", "TX");
    for (j = 0; pmap->rx_qid[j] != NETIF_PORT_ID_INVALID || pmap->tx_qid[j] != NETIF_PORT_ID_INVALID; j++) {
        snprintf(tbuf, sizeof(tbuf), "rx%d/tx%d", j, j);
        snprintf(line, sizeof(line), "    %-12s", tbuf);
        if (pmap->rx_qid[j] != NETIF_PORT_ID_INVALID) {
            snprintf(tbuf2, sizeof(tbuf2), "cpu%d", pmap->rx_qid[j]);
            snprintf(tbuf, sizeof(tbuf), "%-12s", tbuf2);
            strncat(line, tbuf, sizeof(line) - strlen(line));
        } else {
            snprintf(tbuf, sizeof(tbuf), "%-12s", "--");
            strncat(line, tbuf, sizeof(line) - strlen(line));
        }
        if (pmap->tx_qid[j] != NETIF_PORT_ID_INVALID) {
            snprintf(tbuf, sizeof(tbuf), "cpu%d", pmap->tx_qid[j]);
            strncat(line, tbuf, sizeof(line) - strlen(line) - 1);
        } else {
            snprintf(tbuf, sizeof(tbuf), "%-12s", "--");
            strncat(line, tbuf, sizeof(line) - strlen(line) - 1);
        }
        strncat(line, "\n", sizeof(line) - strlen(line));

        left_len = *len - strlen(buf) - 1;
        if (left_len <= 0) {
            RTE_LOG(WARNING, NETIF, "[%s] buffer not enough\n", __func__);
            *len = strlen(buf) + 1;
            return EDPVS_INVAL;
        }
        strncat(buf, line, left_len);
    }

    *len = strlen(buf) + 1;
    return EDPVS_OK;
}

int netif_print_lcore_queue_conf(lcoreid_t cid, char *buf, int *len, bool has_title)
{
    int i, j;
    int max_queue;
    struct netif_port *port;
    struct netif_lcore_conf *plcore = NULL;
    char line[1024], tbuf[32], tbuf2[32];
    int left_len;

    if (unlikely(!buf || !len || *len <= 0))
        return EDPVS_INVAL;

    if (unlikely(rte_get_main_lcore() == cid)) {
        buf[0] = '\0';
        *len = 0;
        return EDPVS_OK;
    }

    i = 0;
    while (lcore_conf[i].nports > 0) {
        if (lcore_conf[i].id == cid) {
            plcore = &lcore_conf[i];
            break;
        }
        ++i;
    }
    if (!plcore) {
        RTE_LOG(WARNING, NETIF, "[%s] cpu%d has no port-queue configured", __func__, cid);
        return EDPVS_NOTEXIST;
    }

    memset(buf, 0, *len);
    for (i = 0; i < plcore->nports; i++) {
        port = netif_port_get(plcore->pqs[i].id);
        assert(port);
        max_queue = (plcore->pqs[i].nrxq > plcore->pqs[i].ntxq ?
                plcore->pqs[i].nrxq : plcore->pqs[i].ntxq);
        for (j = 0; j < max_queue; j++) {
            memset(line, 0, sizeof(line));
            if (has_title) {
                snprintf(tbuf, sizeof(tbuf), "cpu%d", cid);
                snprintf(line, sizeof(line), "%-12s", tbuf);
            }

            if (j < plcore->pqs[i].nrxq)
                snprintf(tbuf2, sizeof(tbuf2), "%s:rx%d",
                        port->name, plcore->pqs[i].rxqs[j].id);
            else
                snprintf(tbuf2, sizeof(tbuf2), "--");
            snprintf(tbuf, sizeof(tbuf), "%-16s", tbuf2);
            strncat(line, tbuf, sizeof(line) - strlen(line) -1);

            if (j < plcore->pqs[i].ntxq)
                snprintf(tbuf2, sizeof(tbuf2), "%s:tx%d",
                        port->name, plcore->pqs[i].txqs[j].id);
            else
                snprintf(tbuf2, sizeof(tbuf2), "--");
            snprintf(tbuf, sizeof(tbuf), "%-16s", tbuf2);
            strncat(line, tbuf, sizeof(line) - strlen(line) - 1);

            left_len = *len - strlen(buf) - 1;
            if (left_len <= 0) {
                RTE_LOG(WARNING, NETIF, "[%s] buffer not enough\n", __func__);
                *len = strlen(buf) + 1;
                return EDPVS_INVAL;
            }
            strncat(buf, line, left_len);
        }
    }

    *len = strlen(buf) + 1;
    return EDPVS_OK;
}

static int netif_print_isol_lcore_conf(lcoreid_t cid, char *buf, int *len, bool has_title)
{
    int left_len;
    char tbuf[32], tbuf2[32];
    struct netif_port *port;
    struct rx_partner *p_curr, *p_next;

    assert(buf && len);
    if (!is_isol_rxq_lcore(cid)) {
        buf[0] = '\0';
        *len = 0;
        return EDPVS_OK;
    }

    memset(buf, 0, *len);
    left_len = *len - 1;

    if (has_title)
        snprintf(buf, left_len, "isol_rxqs on cpu%d: \n", cid);

    list_for_each_entry_safe(p_curr, p_next, &isol_rxq_tab[cid], lnode) {
        assert(p_curr->cid == cid);
        memset(tbuf, 0, sizeof(tbuf));
        memset(tbuf2, 0, sizeof(tbuf2));

        port = netif_port_get(p_curr->pid);
        if (!port)
            return EDPVS_INVAL;
        snprintf(tbuf2, sizeof(tbuf2) - 1, "%s:rx%d(%d/%d)",
                port->name, p_curr->qid,
                rte_ring_count(p_curr->rb),
                rte_ring_free_count(p_curr->rb));
        snprintf(tbuf, sizeof(tbuf) - 1, "%-32s", tbuf2);

        left_len = *len - strlen(buf) - 1;
        strncat(buf, tbuf, left_len);
    }

    *len = strlen(buf) + 1;
    return EDPVS_OK;
}

static inline void netif_tx_burst(lcoreid_t cid, portid_t pid, queueid_t qindex)
{
    int ntx;
    struct netif_queue_conf *txq;
    unsigned i = 0;
    struct rte_mbuf *mbuf_copied = NULL;
    struct netif_port *dev = NULL;

    assert(LCORE_ID_ANY != cid);
    txq = &lcore_conf[lcore2index[cid]].pqs[port2index[cid][pid]].txqs[qindex];
    if (0 == txq->len)
        return;

    dev = netif_port_get(pid);
    if (dev && (dev->flag & NETIF_PORT_FLAG_FORWARD2KNI)) {
        for (; i < txq->len; i++) {
            if (NULL == (mbuf_copied = mbuf_copy(txq->mbufs[i],
                pktmbuf_pool[dev->socket])))
                RTE_LOG(WARNING, NETIF, "%s: fail to copy outbound mbuf into kni\n", __func__);
            else
                kni_ingress(mbuf_copied, dev);
        }
    }

    ntx = rte_eth_tx_burst(pid, txq->id, txq->mbufs, txq->len);
    lcore_stats[cid].opackets += ntx;
    /* do not calculate obytes here in consideration of efficency */
    if (unlikely(ntx < txq->len)) {
        RTE_LOG(INFO, NETIF, "fail to send %d of %d packets on dpdk port %d txq %d\n",
                txq->len - ntx, txq->len, pid, txq->id);
        lcore_stats[cid].dropped += txq->len - ntx;
        do {
            rte_pktmbuf_free(txq->mbufs[ntx]);
        } while (++ntx < txq->len);
    }
}

/* Call me on MASTER lcore */
static inline lcoreid_t get_master_xmit_lcore(void)
{
    static int i = 0;
    lcoreid_t cid;

    cid = lcore_conf[i].id;
    if (netif_lcore_is_fwd_worker(cid)) {
        i++;
    } else {
        cid = lcore_conf[0].id;
        i = 1;
    }

    return cid;
}

struct master_xmit_msg_data {
    struct rte_mbuf *mbuf;
    struct netif_port *dev;
};

static int msg_type_master_xmit_cb(struct dpvs_msg *msg)
{
    struct master_xmit_msg_data *data;
    if (unlikely(NULL == msg || msg->len != sizeof(struct master_xmit_msg_data)))
        return EDPVS_INVAL;

    data = (struct master_xmit_msg_data*)(msg->data);
    if (likely(msg->type == MSG_TYPE_MASTER_XMIT && msg->mode == DPVS_MSG_UNICAST)) {
        //RTE_LOG(DEBUG, NETIF, "Xmit master packet on Slave lcore%u %s\n",
        //        rte_lcore_id(), data->dev->name);
        //fflush(stdout);
        return netif_xmit(data->mbuf, data->dev);
    }

    return EDPVS_INVAL;
}

/* master_xmit_msg should be registered on all slave lcores */
int netif_register_master_xmit_msg(void)
{
    int ret;
    unsigned ii;
    struct dpvs_msg_type mt;
    uint64_t slave_lcore_mask;
    uint8_t slave_lcore_nb;

    memset(&mt, 0, sizeof(mt));
    mt.type = MSG_TYPE_MASTER_XMIT;
    mt.mode = DPVS_MSG_UNICAST;
    mt.prio = MSG_PRIO_HIGH;
    mt.unicast_msg_cb = msg_type_master_xmit_cb;

    netif_get_slave_lcores(&slave_lcore_nb, &slave_lcore_mask);
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if(!(slave_lcore_mask & (1UL << ii)))
            continue;
        mt.cid = ii;
        if (unlikely((ret = msg_type_register(&mt)) < 0)) {
            rte_exit(EXIT_FAILURE, "[%s] fail to register master_xmit_msg,"
                    " exiting ...\n", __func__);
            return ret;
        }
        RTE_LOG(DEBUG, NETIF, "[%s] master_xmit_msg registered on lcore #%d\n",
                __func__, ii);
    }

    return EDPVS_OK;
}

static inline int validate_xmit_mbuf(struct rte_mbuf *mbuf,
                                     const struct netif_port *dev)
{
    int err = EDPVS_OK;

    /* 802.1q VLAN */
    if (mbuf->ol_flags & PKT_TX_VLAN_PKT) {
        if (!(dev->flag & NETIF_PORT_FLAG_TX_VLAN_INSERT_OFFLOAD)) {
            err = vlan_insert_tag(mbuf, htons(ETH_P_8021Q),
                                  mbuf_vlan_tag_get_id(mbuf));
            mbuf->ol_flags &= (~PKT_TX_VLAN_PKT);
            mbuf->vlan_tci = 0;
        }
    }

    return err;
}

int netif_hard_xmit(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    lcoreid_t cid;
    int pid, qindex, ntxq;
    struct netif_queue_conf *txq;
    struct netif_ops *ops;
    int ret = EDPVS_OK;

    if (unlikely(NULL == mbuf || NULL == dev)) {
        if (mbuf)
            rte_pktmbuf_free(mbuf);
        return EDPVS_INVAL;
    }

    ops = dev->netif_ops;
    if (ops && ops->op_xmit)
        return ops->op_xmit(mbuf, dev);

    /* send pkt on current lcore */
    cid = rte_lcore_id();

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM))
        mbuf->l2_len = sizeof(struct rte_ether_hdr);

    if (rte_get_main_lcore() == cid) { // master thread
        struct dpvs_msg *msg;
        struct master_xmit_msg_data msg_data;

        /* NOTE: Ctrl plane send pkts via Data plane, thus no packets are sent on Master lcore.
         * The statistics here is to find out how many packets are sent on Ctrl plane. */
        lcore_stats[cid].opackets++;
        lcore_stats[cid].obytes += mbuf->pkt_len;

        msg_data.mbuf = mbuf;
        msg_data.dev = dev;
        msg = msg_make(MSG_TYPE_MASTER_XMIT, 0, DPVS_MSG_UNICAST, rte_get_main_lcore(),
                sizeof(struct master_xmit_msg_data), &msg_data);
        if (unlikely(NULL == msg)) {
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOMEM;
        }

        cid = get_master_xmit_lcore();
        if (unlikely(ret = msg_send(msg, cid, DPVS_MSG_F_ASYNC, NULL))) {
            RTE_LOG(WARNING, NETIF, "[%s] Send master_xmit_msg(%d) failed\n", __func__, cid);
            rte_pktmbuf_free(mbuf);
        }
        msg_destroy(&msg);
        return ret;
    }

    if (unlikely((ret = validate_xmit_mbuf(mbuf, dev)) != EDPVS_OK)) {
        RTE_LOG(WARNING, NETIF, "%s: validate_xmit_mbuf error\n", __func__);
        rte_pktmbuf_free(mbuf);
        return ret;
    }

    /* port id is determined by routing */
    pid = dev->id;
    ntxq = lcore_conf[lcore2index[cid]].pqs[port2index[cid][pid]].ntxq;
    if (unlikely(ntxq <= 0)) {
        RTE_LOG(WARNING, NETIF, "%s: no txq on device %s, drop the sending packet\n", __func__, dev->name);
        rte_pktmbuf_free(mbuf);
        lcore_stats[cid].dropped++;
        return EDPVS_RESOURCE;
    }
    /* qindex is hashed by physical address of mbuf */
    qindex = (((uint32_t) mbuf->buf_iova) >> 8) % ntxq;
    //RTE_LOG(DEBUG, NETIF, "tx-queue hash(%x) = %d\n", ((uint32_t)mbuf->buf_iova) >> 8, qindex);
    txq = &lcore_conf[lcore2index[cid]].pqs[port2index[cid][pid]].txqs[qindex];

    /* No space left in txq mbufs, transmit cached mbufs immediately */
    if (unlikely(txq->len == NETIF_MAX_PKT_BURST)) {
        netif_tx_burst(cid, pid, qindex);
        txq->len = 0;
    }

    lcore_stats[cid].obytes += mbuf->pkt_len;
    txq->mbufs[txq->len] = mbuf;
    txq->len++;

    /* Cached mbufs transmit later in job `lcore_job_xmit` */

    return EDPVS_OK;
}

int netif_xmit(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    int ret = EDPVS_OK;
    uint16_t mbuf_refcnt;

    if (unlikely(NULL == mbuf || NULL == dev)) {
        if (mbuf)
            rte_pktmbuf_free(mbuf);
        return EDPVS_INVAL;
    }

    if (mbuf->port != dev->id)
        mbuf->port = dev->id;

    /* assert for possible double free */
    mbuf_refcnt = rte_mbuf_refcnt_read(mbuf);
    assert((mbuf_refcnt >= 1) && (mbuf_refcnt <= 64));

    if (dev->flag & NETIF_PORT_FLAG_TC_EGRESS) {
        mbuf = tc_hook(netif_tc(dev), mbuf, TC_HOOK_EGRESS, &ret);
        if (!mbuf)
            return ret;
    }

    return netif_hard_xmit(mbuf, dev);
}

static inline eth_type_t eth_type_parse(const struct rte_ether_hdr *eth_hdr,
                                        const struct netif_port *dev)
{
    if (eth_addr_equal(&dev->addr, &eth_hdr->d_addr))
        return ETH_PKT_HOST;

    if (rte_is_multicast_ether_addr(&eth_hdr->d_addr)) {
        if (rte_is_broadcast_ether_addr(&eth_hdr->d_addr))
            return ETH_PKT_BROADCAST;
        else
            return ETH_PKT_MULTICAST;
    }

    return ETH_PKT_OTHERHOST;
}

int netif_rcv(struct netif_port *dev, __be16 eth_type, struct rte_mbuf *mbuf)
{
    struct pkt_type *pt;
    assert(dev && mbuf && mbuf->port <= NETIF_MAX_PORTS);

    pt = pkt_type_get(eth_type, dev);
    if (!pt)
        return EDPVS_KNICONTINUE;

    return pt->func(mbuf, dev);
}

static int netif_deliver_mbuf(struct netif_port *dev, lcoreid_t cid,
                  struct rte_mbuf *mbuf, bool pkts_from_ring)
{
    int ret = EDPVS_OK;
    struct rte_ether_hdr *eth_hdr;

    assert(mbuf->port <= NETIF_MAX_PORTS);
    assert(dev != NULL);

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    /* reuse mbuf.packet_type, it was RTE_PTYPE_XXX */
    mbuf->packet_type = eth_type_parse(eth_hdr, dev);

    /*
     * In NETIF_PORT_FLAG_FORWARD2KNI mode.
     * All packets received are deep copied and sent to KNI
     * for the purpose of capturing forwarding packets.Since the
     * rte_mbuf will be modified in the following procedure,
     * we should use mbuf_copy instead of rte_pktmbuf_clone.
     */
    if (dev->flag & NETIF_PORT_FLAG_FORWARD2KNI) {
        struct rte_mbuf *mbuf_copied = mbuf_copy(mbuf, pktmbuf_pool[dev->socket]);
        if (likely(mbuf_copied != NULL))
            kni_ingress(mbuf_copied, dev);
        else
            RTE_LOG(WARNING, NETIF, "%s: failed to copy mbuf for kni\n", __func__);
    }

    if (!pkts_from_ring && (dev->flag & NETIF_PORT_FLAG_TC_INGRESS)) {
        mbuf = tc_hook(netif_tc(dev), mbuf, TC_HOOK_INGRESS, &ret);
        if (!mbuf)
            return ret;
    }

    return netif_rcv_mbuf(dev, cid, mbuf, pkts_from_ring);
}

int netif_rcv_mbuf(struct netif_port *dev, lcoreid_t cid, struct rte_mbuf *mbuf, bool pkts_from_ring)
{
    struct rte_ether_hdr *eth_hdr;
    struct pkt_type *pt;
    int err;
    uint16_t data_off;
    bool forward2kni;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    /*
     * do not drop pkt to other hosts (ETH_PKT_OTHERHOST)
     * since virtual devices may have different MAC with
     * underlying device.
     */

    /*
     * handle VLAN
     * if HW offload vlan strip, it's still need vlan module
     * to act as VLAN filter.
     */
    if (eth_hdr->ether_type == htons(ETH_P_8021Q) ||
            mbuf->ol_flags & PKT_RX_VLAN_STRIPPED) {
        if (vlan_rcv(mbuf, netif_port_get(mbuf->port)) != EDPVS_OK)
            goto drop;
        dev = netif_port_get(mbuf->port);
        if (unlikely(!dev))
            goto drop;
        eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    }

    forward2kni = (dev->flag & NETIF_PORT_FLAG_FORWARD2KNI) ? true : false;
    pt = pkt_type_get(eth_hdr->ether_type, dev);
    if (NULL == pt) {
        if (!forward2kni) {
            kni_ingress(mbuf, dev);
            goto done;
        }
        goto drop;
    }

    /* clone arp pkt to every queue */
    if (unlikely(pt->type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP) && !pkts_from_ring)) {
        uint8_t i;
        struct rte_arp_hdr *arp;
        struct rte_mbuf *mbuf_clone;

        arp = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
        if (rte_be_to_cpu_16(arp->arp_opcode) == RTE_ARP_OP_REPLY) {
            for (i = 0; i < DPVS_MAX_LCORE; i++) {
                if ((i == cid) || (!is_lcore_id_fwd(i))
                     || (i == rte_get_main_lcore()))
                    continue;
                /* rte_pktmbuf_clone will not clone pkt.data, just copy pointer! */
                mbuf_clone = rte_pktmbuf_clone(mbuf, pktmbuf_pool[rte_socket_id()]);
                if (unlikely(!mbuf_clone)) {
                    RTE_LOG(WARNING, NETIF, "%s arp reply mbuf clone failed on lcore %d\n",
                            __func__, i);
                    continue;
                }
                err = rte_ring_enqueue(arp_ring[i], mbuf_clone);
                if (unlikely(-EDQUOT == err)) {
                    RTE_LOG(WARNING, NETIF, "%s: arp ring of lcore %d quota exceeded\n",
                            __func__, i);
                } else if (err < 0) {
                    RTE_LOG(WARNING, NETIF, "%s: arp ring of lcore %d enqueue failed\n",
                            __func__, i);
                    rte_pktmbuf_free(mbuf_clone);
                }
            }
        }
    }

    mbuf->l2_len = sizeof(struct rte_ether_hdr);

    /* Remove ether_hdr at the beginning of an mbuf */
    data_off = mbuf->data_off;
    if (unlikely(NULL == rte_pktmbuf_adj(mbuf, sizeof(struct rte_ether_hdr))))
        goto drop;

    err = pt->func(mbuf, dev);

    if (err == EDPVS_KNICONTINUE) {
        if (pkts_from_ring || forward2kni)
            goto drop;
        if (unlikely(NULL == rte_pktmbuf_prepend(mbuf, (mbuf->data_off - data_off))))
            goto drop;
        kni_ingress(mbuf, dev);
    }

done:
    if (!pkts_from_ring) {
        lcore_stats[cid].ibytes += mbuf->pkt_len;
        lcore_stats[cid].ipackets++;
    }
    return EDPVS_OK;

drop:
    rte_pktmbuf_free(mbuf);
    lcore_stats[cid].dropped++;
    return EDPVS_DROP;
}

static int netif_arp_ring_init(void)
{
    char name_buf[RTE_RING_NAMESIZE];
    int socket_id;
    uint8_t cid;

    socket_id = rte_socket_id();
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        snprintf(name_buf, RTE_RING_NAMESIZE, "arp_ring_c%d", cid);
        arp_ring[cid] = rte_ring_create(name_buf, ARP_RING_SIZE, socket_id, RING_F_SC_DEQ);

        if (arp_ring[cid] == NULL)
            rte_panic("create ring:%s failed!\n", name_buf);
    }

    return EDPVS_OK;
}

void lcore_process_packets(struct rte_mbuf **mbufs, lcoreid_t cid, uint16_t count, bool pkts_from_ring)
{
    int i, t;

    /* prefetch packets */
    for (t = 0; t < count && t < NETIF_PKT_PREFETCH_OFFSET; t++)
        rte_prefetch0(rte_pktmbuf_mtod(mbufs[t], void *));

    /* L2 filter */
    for (i = 0; i < count; i++) {
        struct rte_mbuf *mbuf = mbufs[i];
        struct netif_port *dev = netif_port_get(mbuf->port);

        if (unlikely(!dev)) {
            rte_pktmbuf_free(mbuf);
            lcore_stats[cid].dropped++;
            continue;
        }

        /* some protocols like LLDP may still like the originated port */
        MBUF_USERDATA(mbuf, portid_t, MBUF_FIELD_ORIGIN_PORT) = mbuf->port;

        if (dev->type == PORT_TYPE_BOND_SLAVE) {
            dev = dev->bond->slave.master;
            mbuf->port = dev->id;
        }

        mbuf->tx_offload = 0; /* reset l2_len, l3_len, l4_len, ... */

        if (t < count) {
            rte_prefetch0(rte_pktmbuf_mtod(mbufs[t], void *));
            t++;
        }

        /* handler should free mbuf */
        netif_deliver_mbuf(dev, cid, mbuf, pkts_from_ring);
    }
}

static void lcore_process_arp_ring(lcoreid_t cid)
{
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    uint16_t nb_rb;

    nb_rb = rte_ring_dequeue_burst(arp_ring[cid], (void**)mbufs, NETIF_MAX_PKT_BURST, NULL);

    if (nb_rb > 0) {
        lcore_process_packets(mbufs, cid, nb_rb, 1);
    }
}

static void lcore_process_redirect_ring(lcoreid_t cid)
{
    dp_vs_redirect_ring_proc(cid);
}

static void lcore_job_recv_fwd(void *arg)
{
    int i, j;
    portid_t pid;
    lcoreid_t cid;
    struct netif_queue_conf *qconf;

    cid = rte_lcore_id();
    assert(LCORE_ID_ANY != cid);

    for (i = 0; i < lcore_conf[lcore2index[cid]].nports; i++) {
        pid = lcore_conf[lcore2index[cid]].pqs[i].id;
        assert(pid <= bond_pid_end);

        for (j = 0; j < lcore_conf[lcore2index[cid]].pqs[i].nrxq; j++) {
            qconf = &lcore_conf[lcore2index[cid]].pqs[i].rxqs[j];

            lcore_process_arp_ring(cid);
            lcore_process_redirect_ring(cid);
            qconf->len = netif_rx_burst(pid, qconf);

            lcore_stats_burst(&lcore_stats[cid], qconf->len);

            lcore_process_packets(qconf->mbufs, cid, qconf->len, 0);
        }
    }
}

static void lcore_job_xmit(void *args)
{
    int i, j;
    lcoreid_t cid;
    portid_t pid;
    struct netif_queue_conf *qconf;

    cid = rte_lcore_id();
    for (i = 0; i < lcore_conf[lcore2index[cid]].nports; i++) {
        pid = lcore_conf[lcore2index[cid]].pqs[i].id;
#ifdef CONFIG_DPVS_NETIF_DEBUG
        if (unlikely(pid >= dpvs_rte_eth_dev_count())) {
            RTE_LOG(DEBUG, NETIF, "[%s] No enough NICs\n", __func__);
            continue;
        }
#endif
        for (j = 0; j < lcore_conf[lcore2index[cid]].pqs[i].ntxq; j++) {
            qconf = &lcore_conf[lcore2index[cid]].pqs[i].txqs[j];
            if (qconf->len <= 0)
                continue;
            netif_tx_burst(cid, pid, j);
            qconf->len = 0;
        }
    }
}

static int timer_sched_interval_us;
static void lcore_job_timer_manage(void *args)
{
    static uint64_t tm_manager_time[DPVS_MAX_LCORE] = { 0 };
    uint64_t now = rte_get_timer_cycles();
    portid_t cid = rte_lcore_id();

    if (unlikely((now - tm_manager_time[cid]) * 1000000 / g_cycles_per_sec
            > timer_sched_interval_us)) {
        rte_timer_manage();
        tm_manager_time[cid] = now;
    }
}

#define NETIF_JOB_MAX   6

static struct dpvs_lcore_job_array netif_jobs[NETIF_JOB_MAX] = {
    [0] = {
        .role = LCORE_ROLE_FWD_WORKER,
        .job.name = "recv_fwd",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_recv_fwd,
    },

    [1] = {
        .role = LCORE_ROLE_FWD_WORKER,
        .job.name = "xmit",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_xmit,
    },

    [2] = {
        .role = LCORE_ROLE_FWD_WORKER,
        .job.name = "timer_manage",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_timer_manage,
    },

    [3] = {
        .role = LCORE_ROLE_ISOLRX_WORKER,
        .job.name = "isol_pkt_rcv",
        .job.type = LCORE_JOB_LOOP,
        .job.func = recv_on_isol_lcore,
    },

    [4] = {
        .role = LCORE_ROLE_MASTER,
        .job.name = "timer_manage",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_timer_manage,
    },
};

static void netif_lcore_init(void)
{
    int i, err;
    lcoreid_t cid;
    char buf1[1024], buf2[1024];

    timer_sched_interval_us = dpvs_timer_sched_interval_get();

    buf1[0] = buf2[0] = '\0';
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (rte_lcore_is_enabled(cid))
            snprintf(&buf1[strlen(buf1)], sizeof(buf1)-strlen(buf1), "%4d", cid);
        else
            snprintf(&buf2[strlen(buf2)], sizeof(buf2)-strlen(buf2), "%4d", cid);
    }
    RTE_LOG(INFO, NETIF, "LCORE STATUS\n\tenabled: %s\n\tdisabled: %s\n", buf1, buf2);

    /* init isolate rxqueue table */
    isol_rxq_init();

    /* check and set lcore config */
    config_lcores(&worker_list);
    if ((err = check_lcore_conf(rte_lcore_count(), lcore_conf)) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "%s: bad lcore configuration (error code: %d),"
                " exit ...\n", __func__, err);

    /* build lcore fast searching table */
    if ((err = lcore_index_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "%s: lcore_index_init failed (cause: %s), exit ...\n",
                __func__, dpvs_strerror(err));

    /* build port fast searching table */
    port_index_init();

    /* assign lcore roles */
    lcore_role_init();

    /* register lcore jobs*/
    if (g_kni_lcore_id == 0) {
        netif_jobs[5].role = LCORE_ROLE_MASTER;
        dpvs_lcore_job_init(&netif_jobs[5].job, "kni_master_proc",
                            LCORE_JOB_LOOP, kni_lcore_loop, 0);
    } else {
        netif_jobs[5].role = LCORE_ROLE_KNI_WORKER;
        dpvs_lcore_job_init(&netif_jobs[5].job, "kni_loop",
                            LCORE_JOB_LOOP, kni_lcore_loop, 0);
    }

    for (i = 0; i < NELEMS(netif_jobs); i++) {
        err = dpvs_lcore_job_register(&netif_jobs[i].job, netif_jobs[i].role);
        if (err < 0) {
            rte_exit(EXIT_FAILURE, "%s: fail to register lcore job '%s', exit ...\n",
                    __func__, netif_jobs[i].job.name);
            break;
        }
    }
}

static inline void netif_lcore_cleanup(void)
{
    int i;

    for (i = 0; i < NELEMS(netif_jobs); i++) {
        if (dpvs_lcore_job_unregister(&netif_jobs[i].job, netif_jobs[i].role) < 0)
            RTE_LOG(WARNING, NETIF, "%s: fail to unregister lcore job '%s'\n",
                    __func__, netif_jobs[i].job.name);
    }
}

/* always update bond port macaddr and its KNI macaddr together */
static int update_bond_macaddr(struct netif_port *port)
{
    assert(port->type == PORT_TYPE_BOND_MASTER);

    if (rte_eth_macaddr_get(port->id, &port->addr))
        return EDPVS_NOTEXIST;

    if (kni_dev_exist(port)) {
        /* if kni device isn't link up, linux_set_if_mac would fail(Timer expired),
         * and in this case the warning can be ingored.*/
        linux_set_if_mac(port->kni.name, (unsigned char *)&port->addr);
        rte_ether_addr_copy(&port->addr, &port->kni.addr);
    }

    return EDPVS_OK;
}

static inline void free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
    unsigned i;

    if (pkts == NULL)
        return;

    for (i = 0; i < num; i++) {
        rte_pktmbuf_free(pkts[i]);
        pkts[i] = NULL;
    }
}

/********************************************** kni *************************************************/

void kni_ingress(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    if (!kni_dev_exist(dev))
        goto freepkt;

    // TODO: Use `rte_ring_enqueue_bulk` for better performance.
    if (unlikely(rte_ring_enqueue(dev->kni.rx_ring, (void *)mbuf) != 0))
        goto freepkt;
    return;

freepkt:
#ifdef CONFIG_DPVS_NETIF_DEBUG
    RTE_LOG(INFO, NETIF, "%s: fail to enqueue packet to kni rx_ring\n", __func__);
#endif
    rte_pktmbuf_free(mbuf);
}

static void kni_egress(struct netif_port *port)
{
    unsigned i, npkts;
    struct rte_mbuf *kni_pkts_burst[NETIF_MAX_PKT_BURST];

    if (!kni_dev_exist(port))
        return;

    npkts = rte_kni_rx_burst(port->kni.kni, kni_pkts_burst, NETIF_MAX_PKT_BURST);
    if (unlikely(npkts > NETIF_MAX_PKT_BURST)) {
        RTE_LOG(WARNING, NETIF, "%s: fail to recieve pkts from kni\n", __func__);
        return;
    }

    for (i = 0; i < npkts; i++) {
        if (unlikely(netif_xmit(kni_pkts_burst[i], port) != EDPVS_OK)) {
#ifdef CONFIG_DPVS_NETIF_DEBUG
            RTE_LOG(INFO, NETIF, "%s: fail to transmit kni packet", __func__);
#endif
        }
    }
}

static void kni_egress_process(void)
{
    struct netif_port *dev;
    portid_t id;

    for (id = 0; id < g_nports; id++) {
        dev = netif_port_get(id);
        if (!dev || !kni_dev_exist(dev))
            continue;

        kni_handle_request(dev);
        kni_egress(dev);
    }
}

/*
 * KNI rx rte_ring use mode as multi-producers and the single-consumer.
 */
static void kni_ingress_process(void)
{
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    struct netif_port *dev;
    uint16_t i, pkt_total, pkt_sent;
    portid_t id;
    lcoreid_t cid = rte_lcore_id();

    for (id = 0; id < g_nports; id++) {
        dev = netif_port_get(id);
        if (!dev || !kni_dev_exist(dev))
            continue;

        pkt_total = rte_ring_dequeue_burst(dev->kni.rx_ring, (void**)mbufs,
                                       NETIF_MAX_PKT_BURST, NULL);
        if (pkt_total == 0)
            continue;
        lcore_stats[cid].ipackets += pkt_total;
        for (i = 0; i < pkt_total; i++)
            lcore_stats[cid].ibytes += mbufs[i]->pkt_len;
        pkt_sent = rte_kni_tx_burst(dev->kni.kni, mbufs, pkt_total);

        if (unlikely(pkt_sent < pkt_total)) {
#ifdef CONFIG_DPVS_NETIF_DEBUG
            RTE_LOG(INFO, NETIF, "%s: sent %d packets to kni %s, loss %.2f%%\n",
                    __func__, pkt_total, dev->kni.name,
                    (pkt_total-pkt_sent)*100.0/pkt_total);
#endif
            free_mbufs(&(mbufs[pkt_sent]), pkt_total - pkt_sent);
            lcore_stats[cid].dropped += (pkt_total - pkt_sent);
        }
        pkt_total = 0;
    }
}

/*
 * note: kni_ingress_flow_xmit_vlan_trunk supports both vlan trunk and vlan access
 */
static inline void kni_ingress_flow_xmit_vlan_trunk(struct netif_port *dev,
            lcoreid_t cid, struct netif_queue_conf *qconf)
{
    int i, left, right, len;
    unsigned pkt_total, pkt_sent;
    struct rte_ether_hdr *eh;
    struct rte_mbuf *mbuf;
    struct netif_port *rdev;

    for (i = 0; i < qconf->len; i++) {
        // the received packets may from multiple vlans,
        // we have to process them one by one
        mbuf = qconf->mbufs[i];
        eh = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
        if (eh->ether_type == htons(ETH_P_8021Q) ||
                mbuf->ol_flags & PKT_RX_VLAN_STRIPPED) {
            vlan_rcv(mbuf, dev);
        } else if (dev->type == PORT_TYPE_BOND_MASTER) {
            mbuf->port = dev->id;
        }
        /*
         * The performance is astonishingly poor (as observed only about 3K pps,
         * dozens multiple less than normal) if xmit packets to kni one at a time!
         *
        if (rte_kni_tx_burst(dev->kni.kni, qconf->mbufs, 1) != 1) {
            rte_pktmbuf_free(qconf->mbufs[i]);
            lcore_stats[cid].dropped++;
        }
        */
    }

    // reorder mbufs and xmit to kni in batch for each vlan
    len = qconf->len;
    while (len > 0) {
        left = 0;
        right = len - 1;
        mbuf = qconf->mbufs[right];
        while (left < right) {
            while (left < right && qconf->mbufs[left]->port != mbuf->port)
                left++;
            qconf->mbufs[right] = qconf->mbufs[left];
            while (left < right && qconf->mbufs[right]->port == mbuf->port)
                right--;
            qconf->mbufs[left] = qconf->mbufs[right];
        }
        qconf->mbufs[right] = mbuf;

        rdev = netif_port_get(mbuf->port);
        if (unlikely(!rdev || !kni_dev_exist(rdev)))
            rdev = dev;
        pkt_total = len - right;
        //pkt_sent = rte_kni_tx_burst(rdev->kni.kni, &qconf->mbufs[right], pkt_total);
        pkt_sent = rte_ring_enqueue_bulk(rdev->kni.rx_ring,
                    (void *const *)&qconf->mbufs[right], pkt_total, NULL);
        if (unlikely(pkt_sent < pkt_total)) {
#ifdef CONFIG_DPVS_NETIF_DEBUG
            RTE_LOG(INFO, NETIF, "%s: enqueue %d packets to kni %s, loss %.2f%%\n",
                    __func__, pkt_total, rdev->kni.name,
                    (pkt_total-pkt_sent)*100.0/pkt_total);
#endif
            free_mbufs(&(qconf->mbufs[right+pkt_sent]), pkt_total - pkt_sent);
            lcore_stats[cid].dropped += pkt_total - pkt_sent;
        }
        len = right;
    }

    qconf->len = 0;
}

static inline void kni_ingress_flow_xmit_vlan_access(struct netif_port *dev,
            lcoreid_t cid, struct netif_queue_conf *qconf)
{
    unsigned pkt_sent;

    // pkt_sent = rte_kni_tx_burst(dev->kni.kni, qconf->mbufs, qconf->len);
    pkt_sent = rte_ring_enqueue_bulk(dev->kni.rx_ring, (void *const *)qconf->mbufs, qconf->len, NULL);

    if (unlikely(pkt_sent < qconf->len)) {
#ifdef CONFIG_DPVS_NETIF_DEBUG
        RTE_LOG(INFO, NETIF, "%s: enqueue %d packets to rx_ring of kni %s, loss %.2f%%\n",
                __func__, qconf->len, dev->kni.name,
                (qconf->len-pkt_sent)*100.0/qconf->len);
#endif
        free_mbufs(&(qconf->mbufs[pkt_sent]), qconf->len - pkt_sent);
        lcore_stats[cid].dropped += qconf->len - pkt_sent;
    }

    qconf->len = 0;
}

/*
 * Receive packets matched kni ip addresses with rte_flow from KNI worker
 */
static void kni_ingress_flow_process(void)
{
    int i, j;
    portid_t pid;
    lcoreid_t cid;
    struct netif_port *dev;
    struct netif_queue_conf *qconf;

    cid = rte_lcore_id(); // kni worker
    assert(LCORE_ID_ANY != cid);

    for (i = 0; i < lcore_conf[lcore2index[cid]].nports; i++) {
        pid = lcore_conf[lcore2index[cid]].pqs[i].id;
        assert(pid <= bond_pid_end);
        dev = netif_port_get(pid);
        if (!dev || !kni_dev_exist(dev))
            continue;
        for (j = 0; j < lcore_conf[lcore2index[cid]].pqs[i].nrxq; j++) {
            qconf = &lcore_conf[lcore2index[cid]].pqs[i].rxqs[j];
            qconf->len = netif_rx_burst(pid, qconf);
            lcore_stats_burst(&lcore_stats[cid], qconf->len);
            if (!qconf->len)
                continue;
            if (dev->vlan_info)
                kni_ingress_flow_xmit_vlan_trunk(dev, cid, qconf);
            else
                kni_ingress_flow_xmit_vlan_access(dev, cid, qconf);
        }
    }
}

/*
 * Use separate core to convey kni traffic if KNI lcore worker is configued.
 */
void kni_lcore_loop(void *dummy)
{
    /* This is a lazy solution.
     * It's better to schedule the tasks with an independent job on kni worker instead. */
    if (g_kni_lcore_id != 0) {
        kni_ingress_flow_process();
        lcore_job_xmit(NULL);
    }

    kni_ingress_process();
    kni_egress_process();
}

/********************************************* port *************************************************/

static void netif_dump_rss_reta(struct netif_port *port)
{
    int i, len, pos;
    uint32_t reta_id, reta_pos;
    char buf[ETH_RSS_RETA_SIZE_512 * 8];
    struct rte_eth_rss_reta_entry64 reta_info[RETA_CONF_SIZE];

    if (port->type != PORT_TYPE_GENERAL && port->type != PORT_TYPE_BOND_SLAVE)
        return;

    if (unlikely(port->dev_info.reta_size == 0))
        if (unlikely(rte_eth_dev_info_get(port->id, &port->dev_info)))
            return;

    memset(reta_info, 0, sizeof(reta_info));
    for (i = 0; i < port->dev_info.reta_size; i++)
        reta_info[i / RTE_RETA_GROUP_SIZE].mask = UINT64_MAX;

    if (unlikely(rte_eth_dev_rss_reta_query(port->id, reta_info,
                    port->dev_info.reta_size)))
        return;

    buf[0] = '\0';
    len = pos = 0;
    for (i = 0; i < port->dev_info.reta_size; i++) {
        reta_id = i / RTE_RETA_GROUP_SIZE;
        reta_pos = i % RTE_RETA_GROUP_SIZE;
        if (i % 8 == 0) {
            len = snprintf(&buf[pos], sizeof(buf) - pos, "\n%4d: ", i);
            if (len >= sizeof(buf) - pos) {
                snprintf(&buf[sizeof(buf)-16], 16, "%s", "(truncated)");
                break;
            }
            pos += len;
        }
        len = snprintf(&buf[pos], sizeof(buf)-pos, "%-4d", reta_info[reta_id].reta[reta_pos]);
        if (len >= sizeof(buf) - pos) {
            snprintf(&buf[sizeof(buf)-16], 16, "%s", "(truncated)");
            break;
        }
        pos += len;
    }

    RTE_LOG(INFO, NETIF, "RSS RETA(%s):%s\n", port->name, buf);
}

static int __netif_update_rss_reta(struct netif_port *port)
{
    int i, err;
    int nrssq = NETIF_MAX_QUEUES;
    queueid_t rssq[NETIF_MAX_QUEUES];
    uint32_t reta_id, reta_pos;
    struct rte_eth_rss_reta_entry64 reta_conf[RETA_CONF_SIZE];

    if (port->type != PORT_TYPE_GENERAL && port->type != PORT_TYPE_BOND_SLAVE)
        return EDPVS_NOTSUPP;

    if (port->type == PORT_TYPE_BOND_SLAVE)
        err = get_configured_rss_queues(port->bond->slave.master->id, rssq, &nrssq);
    else
        err = get_configured_rss_queues(port->id, rssq, &nrssq);
    if (err != EDPVS_OK)
        return err;
#ifdef CONFIG_DPVS_NETIF_DEBUG
    printf("RSS QUEUES(%s): ", port->name);
    for (i = 0; i < nrssq; i++) {
        printf("%-4d", rssq[i]);
    }
    printf("\n");
#endif

    memset(reta_conf, 0, sizeof(reta_conf));
    for (i = 0; i < port->dev_info.reta_size; i++) {
        reta_id = i / RTE_RETA_GROUP_SIZE;
        reta_pos = i % RTE_RETA_GROUP_SIZE;
        reta_conf[reta_id].mask = UINT64_MAX;
        reta_conf[reta_id].reta[reta_pos] = (uint16_t)(rssq[i % nrssq]);
    }

    if (rte_eth_dev_rss_reta_update(port->id, reta_conf, port->dev_info.reta_size))
        return EDPVS_DPDKAPIFAIL;

    netif_dump_rss_reta(port);
    return EDPVS_OK;
}

static int netif_update_rss_reta(struct netif_port *port)
{
    switch (port->type) {
        case PORT_TYPE_GENERAL:
            return __netif_update_rss_reta(port);
        case PORT_TYPE_BOND_MASTER:
        {
            // notes:
            // rss reta of bonding slaves must be configured after bonding devices bootup,
            // or it would be reset when bonding device bootup.
            int i, err;
            for (i = 0; i < port->bond->master.slave_nb; i++) {
                err = __netif_update_rss_reta(port->bond->master.slaves[i]);
                if (err != EDPVS_OK)
                    return err;
            }
            return EDPVS_OK;
        }
        default:
            return EDPVS_OK;
    }
}

static inline int port_tab_hashkey(portid_t id)
{
    return id & NETIF_PORT_TABLE_MASK;
}

static unsigned int port_ntab_hashkey(const char *name, size_t len)
{
    int i;
    unsigned int hash=1315423911;
    for (i = 0; i < len; i++)
    {
        if (name[i] == '\0')
            break;
        hash^=((hash<<5)+name[i]+(hash>>2));
    }

    return (hash % NETIF_PORT_TABLE_BUCKETS);
}

static inline void port_tab_init(void)
{
    int i;
    for (i = 0; i < NETIF_PORT_TABLE_BUCKETS; i++)
        INIT_LIST_HEAD(&port_tab[i]);
}

static inline void port_ntab_init(void)
{
    int i;
    for (i = 0; i < NETIF_PORT_TABLE_BUCKETS; i++)
        INIT_LIST_HEAD(&port_ntab[i]);
}

static inline int port_name_alloc(portid_t pid, char *pname, size_t buflen)
{
    assert(pname && buflen > 0);
    memset(pname, 0, buflen);
    if (is_physical_port(pid)) {
        struct port_conf_stream *current_cfg;
        list_for_each_entry_reverse(current_cfg, &port_list, port_list_node) {
            if (current_cfg->port_id < 0) {
                current_cfg->port_id = pid;
                if (current_cfg->name[0])
                    snprintf(pname, buflen, "%s", current_cfg->name);
                else
                    snprintf(pname, buflen, "dpdk%d", pid);
                return EDPVS_OK;
            }
        }
        RTE_LOG(ERR, NETIF, "%s: not enough ports configured in dpvs.conf\n", __func__);
        return EDPVS_NOTEXIST;
    } else if (is_bond_port(pid)) {
        struct bond_conf_stream *current_cfg;
        list_for_each_entry_reverse(current_cfg, &bond_list, bond_list_node) {
            if (current_cfg->port_id == pid) {
                if (current_cfg->name[0])
                    snprintf(pname, buflen, "%s", current_cfg->name);
                else
                    snprintf(pname, buflen, "bond%d", pid - bond_pid_base);
                return EDPVS_OK;
            }
        }
        return EDPVS_NOTEXIST;
    }

    return EDPVS_INVAL;
}

static inline portid_t netif_port_id_alloc(void)
{
    return port_id_end++;
}

portid_t netif_port_count(void)
{
    return port_id_end;
}

struct netif_port *netif_alloc(portid_t id, size_t priv_size, const char *namefmt,
                               unsigned int nrxq, unsigned int ntxq,
                               void (*setup)(struct netif_port *))
{
    int ii;
    struct netif_port *dev;
    static const uint8_t mac_zero[6] = {0};

    size_t alloc_size;

    alloc_size = sizeof(struct netif_port);
    if (priv_size) {
        /* ensure 32-byte alignment of private area */
        alloc_size = __ALIGN_KERNEL(alloc_size, NETIF_ALIGN);
        alloc_size += priv_size;
    }

    dev = rte_zmalloc("netif", alloc_size, RTE_CACHE_LINE_SIZE);
    if (!dev) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        return NULL;
    }

    if (id != NETIF_PORT_ID_INVALID && !netif_port_get(id))
        dev->id = id;
    else
        dev->id = netif_port_id_alloc();

    if (strstr(namefmt, "%d"))
        snprintf(dev->name, sizeof(dev->name), namefmt, dev->id);
    else
        snprintf(dev->name, sizeof(dev->name), "%s", namefmt);

    rte_rwlock_init(&dev->dev_lock);
    dev->socket = SOCKET_ID_ANY;
    dev->hw_header_len = sizeof(struct rte_ether_hdr); /* default */

    if (setup)
        setup(dev);

    /* flag may set by setup() routine */
    dev->flag |= NETIF_PORT_FLAG_ENABLED;
    dev->nrxq = nrxq;
    dev->ntxq = ntxq;

    /* virtual dev has no NUMA-node */
    if (dev->socket == SOCKET_ID_ANY)
        dev->socket = rte_socket_id();
    dev->mbuf_pool = pktmbuf_pool[dev->socket];

    if (memcmp(&dev->addr, &mac_zero, sizeof(dev->addr)) == 0) {
        //TODO: use random lladdr ?
    }

    if (dev->mtu == 0)
        dev->mtu = ETH_DATA_LEN;

    netif_mc_init(dev);

    dev->in_ptr = rte_zmalloc(NULL, sizeof(struct inet_device), RTE_CACHE_LINE_SIZE);
    if (!dev->in_ptr) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        rte_free(dev);
        return NULL;
    }
    dev->in_ptr->dev = dev;
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        INIT_LIST_HEAD(&dev->in_ptr->ifa_list[ii]);
        INIT_LIST_HEAD(&dev->in_ptr->ifm_list[ii]);
    }

    if (tc_init_dev(dev) != EDPVS_OK) {
        RTE_LOG(ERR, NETIF, "%s: fail to init TC\n", __func__);
        rte_free(dev);
        return NULL;
    }

    return dev;
}

int netif_free(struct netif_port *dev)
{
    // TODO:
    return EDPVS_OK;
}

static int bond_set_mc_list(struct netif_port *dev)
{
    int i, err = EDPVS_OK;
    struct netif_port *slave;

    if (dev->type != PORT_TYPE_BOND_MASTER)
        return EDPVS_INVAL;

    for (i = 0; i < dev->bond->master.slave_nb; i++) {
        slave = dev->bond->master.slaves[i];

        rte_rwlock_write_lock(&slave->dev_lock);
        err = __netif_mc_sync_multiple(slave, dev, dev->bond->master.slave_nb);
        rte_rwlock_write_unlock(&slave->dev_lock);

        if (err != EDPVS_OK) {
            RTE_LOG(WARNING, NETIF, "%s: fail to sync %s's mcast list - %d\n",
                    __func__, slave->name, err);
            break;
        }
    }

    return err;
}

static int dpdk_set_mc_list(struct netif_port *dev)
{
    struct rte_ether_addr addrs[NETIF_MAX_HWADDR];
    int err;
    size_t naddr = NELEMS(addrs);

    if (rte_eth_allmulticast_get(dev->id) == 1)
        return EDPVS_OK;

    err = __netif_mc_dump(dev, 0, addrs, &naddr);
    if (err != EDPVS_OK)
        return err;

    RTE_LOG(DEBUG, NETIF, "%s: configuring %lu multicast hw-addrs\n", dev->name, naddr);
    err = rte_eth_dev_set_mc_addr_list(dev->id, addrs, naddr);
    if (err) {
        RTE_LOG(WARNING, NETIF, "%s: rte_eth_dev_set_mc_addr_list failed -- %s,"
                "enable all multicast\n", dev->name, rte_strerror(-err));
        rte_eth_allmulticast_enable(dev->id);
        return EDPVS_OK;
    }

    return EDPVS_OK;
}

static int netif_op_get_xstats(struct netif_port *dev, netif_nic_xstats_get_t **pget)
{
    int i, nentries, err;
    struct rte_eth_xstat *xstats = NULL;
    struct rte_eth_xstat_name *xstats_names = NULL;
    netif_nic_xstats_get_t *get = NULL;

    nentries = rte_eth_xstats_get(dev->id, NULL, 0);
    if (nentries < 0)
        return EDPVS_DPDKAPIFAIL;

    get = rte_calloc("xstats_get", 1, sizeof(*get) + nentries * sizeof(struct netif_nic_xstats_entry), 0);
    if (unlikely(!get))
        return EDPVS_NOMEM;
    xstats = rte_calloc("xstats", 1, nentries * sizeof(struct rte_eth_xstat), 0);
    if (unlikely(!xstats)) {
        err = EDPVS_NOMEM;
        goto errout;
    }
    xstats_names = rte_calloc("xstats_names", 1, nentries * sizeof(struct rte_eth_xstat_name), 0);
    if (unlikely(!xstats_names)) {
        err = EDPVS_NOMEM;
        goto errout;
    }

    err = rte_eth_xstats_get(dev->id, xstats, nentries);
    if (err < 0 || err != nentries)
        goto errout;
    err = rte_eth_xstats_get_names(dev->id, xstats_names, nentries);
    if (err < 0 || err != nentries)
        goto errout;
    get->pid = dev->id;
    get->nentries = nentries;
    for (i = 0; i < nentries; i++) {
        get->entries[i].id = xstats[i].id;
        get->entries[i].val = xstats[i].value;
        rte_memcpy(get->entries[i].name, xstats_names[i].name, sizeof(get->entries[i].name)-1);
    }

    *pget = get;
    rte_free(xstats);
    rte_free(xstats_names);
    return EDPVS_OK;
errout:
    if (xstats)
        rte_free(xstats);
    if (xstats_names)
        rte_free(xstats_names);
    if (get)
        rte_free(get);
    if (err == EDPVS_OK)
        err = EDPVS_RESOURCE;
    *pget = NULL;
    return err;
}

static struct netif_ops dpdk_netif_ops = {
    .op_set_mc_list      = dpdk_set_mc_list,
    .op_get_xstats       = netif_op_get_xstats,
};

static struct netif_ops bond_netif_ops = {
    .op_update_addr      = update_bond_macaddr,
    .op_set_mc_list      = bond_set_mc_list,
    .op_get_xstats       = netif_op_get_xstats,
};

static inline void setup_dev_of_flags(struct netif_port *port)
{
    port->flag |= NETIF_PORT_FLAG_ENABLED;

    /* tx offload conf and flags */
    if (port->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)
        port->flag |= NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD;

    if (port->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)
        port->flag |= NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD;

    if (port->dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)
        port->flag |= NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD;

    /* FIXME: may be a bug in dev_info get for virtio device,
     *        set the txq_of_flags manually for this type device */
    if (strncmp(port->dev_info.driver_name, "net_virtio", strlen("net_virtio")) == 0) {
        port->flag |= NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD;
        port->flag &= ~NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD;
        port->flag &= ~NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD;
    }

    /*
     * we may have multiple vlan dev on one rte_ethdev,
     * and mbuf->vlan_tci is RX only!
     * while there's only one PVID (DEV_TX_OFFLOAD_VLAN_INSERT),
     * to make things easier, do not support TX VLAN instert offload.
     * or we have to check if VID is PVID (than to tx offload it).
     */
#if 0
    if (dev_info->tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT) {
        port->flag |= NETIF_PORT_FLAG_TX_VLAN_INSERT_OFFLOAD;
        port->dev_conf.txmode.hw_vlan_insert_pvid = 1;
        rte_eth_dev_set_vlan_pvid();
    }
#endif

    /* rx offload conf and flags */
    if (port->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_STRIP) {
        port->flag |= NETIF_PORT_FLAG_RX_VLAN_STRIP_OFFLOAD;
        port->dev_conf.rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;
    }
    if (port->dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM)
        port->flag |= NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD;

    /* enable lldp on physical port */
    if (is_physical_port(port->id))
        port->flag |= NETIF_PORT_FLAG_LLDP;
}

struct netif_port* netif_port_get(portid_t id)
{
    int hash = port_tab_hashkey(id);
    struct netif_port *port;
    assert(id <= NETIF_MAX_PORTS);

    list_for_each_entry(port, &port_tab[hash], list) {
        if (port->id == id) {
            return port;
        }
    }

    return NULL;
}

struct netif_port* netif_port_get_by_name(const char *name)
{
    int nhash;
    struct netif_port *port;

    if (!name || strlen(name) <= 0)
        return NULL;

    nhash = port_ntab_hashkey(name, strlen(name));
    list_for_each_entry(port, &port_ntab[nhash], nlist) {
        if (!strcmp(port->name, name)) {
            return port;
        }
    }

    return NULL;
}

int netif_get_queue(struct netif_port *port, lcoreid_t cid, queueid_t *qid)
{
    static unsigned idx[DPVS_MAX_LCORE] = { 0 };
    struct netif_port_conf *qconf;
    static const unsigned IDX_MAX = (1 << sizeof(unsigned)) - 2;

    assert(port && port->netif_ops && qid);

    if (port->netif_ops->op_get_queue)
        return port->netif_ops->op_get_queue(port, cid, qid);

    /* for device (like dpdk/bonding) has lcore_conf */
    *qid = NETIF_MAX_QUEUES;
    if (unlikely(NULL == port || rte_lcore_is_enabled(cid) == 0))
        return EDPVS_INVAL;

    qconf = &lcore_conf[lcore2index[cid]].pqs[port2index[cid][port->id]];
    if (unlikely(!qconf->nrxq))
        return EDPVS_INVAL;

    if (++idx[cid] > IDX_MAX)
        idx[cid] = 0;

    *qid = qconf->rxqs[idx[cid] % qconf->nrxq].id;
    return EDPVS_OK;
}

int netif_get_link(struct netif_port *dev, struct rte_eth_link *link)
{
    assert(dev && dev->netif_ops && link);

    if (dev->netif_ops->op_get_link)
        return dev->netif_ops->op_get_link(dev, link);

    rte_eth_link_get_nowait((uint8_t)dev->id, link);
    return EDPVS_OK;
}

int netif_get_promisc(struct netif_port *dev, bool *promisc)
{
    assert(dev && dev->netif_ops && promisc);

    if (dev->netif_ops->op_get_promisc)
        return dev->netif_ops->op_get_promisc(dev, promisc);

    *promisc = rte_eth_promiscuous_get(dev->id) ? true : false;
    return EDPVS_OK;
}

int netif_get_allmulticast(struct netif_port *dev, bool *allmulticast)
{
    assert(dev && dev->netif_ops && allmulticast);

    if (dev->netif_ops->op_get_allmulticast)
        return dev->netif_ops->op_get_allmulticast(dev, allmulticast);

    *allmulticast = rte_eth_allmulticast_get(dev->id) ? true : false;
    return EDPVS_OK;
}

int netif_get_stats(struct netif_port *dev, struct rte_eth_stats *stats)
{
    int err;
    assert(dev && dev->netif_ops && stats);

    if (dev->netif_ops->op_get_stats)
        return dev->netif_ops->op_get_stats(dev, stats);

    err = rte_eth_stats_get((uint8_t)dev->id, stats);
    if (err)
        return EDPVS_DPDKAPIFAIL;

    return EDPVS_OK;
}

int netif_get_xstats(struct netif_port *dev, netif_nic_xstats_get_t **xstats)
{
    assert (dev && dev->netif_ops && xstats);

    if (dev->netif_ops->op_get_xstats)
        return dev->netif_ops->op_get_xstats(dev, xstats);

    return EDPVS_NOTSUPP;
}

int netif_port_conf_get(struct netif_port *port, struct rte_eth_conf *eth_conf)
{

    if (unlikely(NULL == port))
        return EDPVS_INVAL;

    rte_rwlock_read_lock(&port->dev_lock);
    *eth_conf = port->dev_conf;
    rte_rwlock_read_unlock(&port->dev_lock);

    return EDPVS_OK;
}

int netif_port_conf_set(struct netif_port *port, const struct rte_eth_conf *conf)
{
    if (unlikely(NULL == port || NULL == conf))
        return EDPVS_INVAL;

    rte_rwlock_write_lock(&port->dev_lock);
    memcpy(&port->dev_conf, conf, sizeof(struct rte_eth_conf));
    rte_rwlock_write_unlock(&port->dev_lock);

    return EDPVS_OK;
};

static inline void port_mtu_set(struct netif_port *port)
{
    int ii;
    uint16_t mtu, t_mtu;

    rte_eth_dev_get_mtu(port->id, &mtu);

    if (port->type != PORT_TYPE_BOND_MASTER) {
        port->mtu = mtu;
        return;
    }

    for (ii = 0; ii < port->bond->master.slave_nb; ii++) {
        t_mtu = 65535;
        rte_eth_dev_get_mtu((uint8_t)port->bond->master.slaves[ii]->id, &t_mtu);
        if (!mtu || t_mtu < mtu)
            mtu = t_mtu;
    }
    port->mtu = mtu;

    rte_eth_dev_set_mtu((uint8_t)port->id,port->mtu);

}

static int rss_resolve_proc(char *rss)
{
    int rss_value = 0;

    if (!strcmp(rss, "all"))
        rss_value = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP;
    else if (!strcmp(rss, "ip"))
        rss_value = ETH_RSS_IP;
    else if (!strcmp(rss, "tcp"))
        rss_value = ETH_RSS_TCP;
    else if (!strcmp(rss, "udp"))
        rss_value = ETH_RSS_UDP;
    else if (!strcmp(rss, "sctp"))
        rss_value = ETH_RSS_SCTP;
    else if (!strcmp(rss, "ether"))
        rss_value = ETH_RSS_L2_PAYLOAD;
    else if (!strcmp(rss, "port"))
        rss_value = ETH_RSS_PORT;
    else if (!strcmp(rss, "tunnel"))
        rss_value = ETH_RSS_TUNNEL;

    return rss_value;
}

/* check and adapt device offloading/rss features */
static void adapt_device_conf(portid_t port_id, uint64_t *rss_hf,
        uint64_t *rx_offload, uint64_t *tx_offload)
{
    struct rte_eth_dev_info dev_info;

    rte_eth_dev_info_get(port_id, &dev_info);

    if ((dev_info.flow_type_rss_offloads | *rss_hf) !=
        dev_info.flow_type_rss_offloads) {
        RTE_LOG(WARNING, NETIF,
                "Ethdev port_id=%u invalid rss_hf: 0x%"PRIx64", valid value: 0x%"PRIx64"\n",
                port_id, *rss_hf, dev_info.flow_type_rss_offloads);
        /* mask the unsupported rss_hf */
        *rss_hf &= dev_info.flow_type_rss_offloads;
    }

    if ((dev_info.rx_offload_capa | *rx_offload) != dev_info.rx_offload_capa) {
        RTE_LOG(WARNING, NETIF,
                "Ethdev port_id=%u invalid rx_offload: 0x%"PRIx64", valid value: 0x%"PRIx64"\n",
                port_id, *rx_offload, dev_info.rx_offload_capa);
        /* mask the unsupported rx_offload */
        *rx_offload &= dev_info.rx_offload_capa;
    }

    if ((dev_info.tx_offload_capa | *tx_offload) != dev_info.tx_offload_capa) {
        RTE_LOG(WARNING, NETIF,
                "Ethdev port_id=%u invalid tx_offload: 0x%"PRIx64", valid value: 0x%"PRIx64"\n",
                port_id, *tx_offload, dev_info.tx_offload_capa);
        /* mask the unsupported tx_offload */
        *tx_offload &= dev_info.tx_offload_capa;
    }
}

/* fill in rx/tx queue configurations, including queue number,
 * decriptor number, bonding device's rss */
static void fill_port_config(struct netif_port *port, char *promisc_on, char *allmulticast)
{
    assert(port);

    char rss[256] = {0};
    int index = 0;
    int rss_index = 0;
    struct port_conf_stream *cfg_stream;

    if (port->type == PORT_TYPE_BOND_SLAVE) {
        /* bond slaves do not have worker configured */
        port->nrxq = port_rx_queues_get(port->bond->slave.master->id);
        port->ntxq = port_tx_queues_get(port->bond->slave.master->id);
    } else {
        port->nrxq = port_rx_queues_get(port->id);
        port->ntxq = port_tx_queues_get(port->id);
    }

    cfg_stream = get_port_conf_stream(port->name);
    if (cfg_stream) {
        /* device specific configurations from cfgfile */
        port->dev_conf.rx_adv_conf.rss_conf.rss_hf = 0;
        for (index = 0; index < strlen(cfg_stream->rss); index++) {
            if (cfg_stream->rss[index] == ' ') {
                continue;
            } else if (cfg_stream->rss[index] != '|') {
                rss[rss_index++] = cfg_stream->rss[index];
            } else {
                rss[rss_index] = '\0';
                rss_index = 0;
                port->dev_conf.rx_adv_conf.rss_conf.rss_hf |= rss_resolve_proc(rss);
                memset(rss, 0, sizeof(rss));
            }
        }

        if (rss[0]) {
            port->dev_conf.rx_adv_conf.rss_conf.rss_hf |= rss_resolve_proc(rss);
        }

        port->mtu = cfg_stream->mtu;
        if (cfg_stream->rx_queue_nb > 0 && port->nrxq > cfg_stream->rx_queue_nb) {
            RTE_LOG(WARNING, NETIF, "%s: rx-queues configured in workers (%d) != "
                    "rx-queues configured in device (%d), setup %d rx-queues for %s\n",
                    port->name, port->nrxq, cfg_stream->rx_queue_nb,
                    port->nrxq, port->name);
        }
        if (cfg_stream->tx_queue_nb > 0 && port->ntxq > cfg_stream->tx_queue_nb) {
            RTE_LOG(WARNING, NETIF, "%s: tx-queues configured in workers (%d) != "
                    "tx-queues configured in device (%d), setup %d tx-queues for %s\n",
                    port->name, port->ntxq, cfg_stream->tx_queue_nb,
                    port->ntxq, port->name);
        }
        port->rxq_desc_nb = cfg_stream->rx_desc_nb;
        port->txq_desc_nb = cfg_stream->tx_desc_nb;
    } else {
        /* using default configurations */
        port->rxq_desc_nb = NETIF_NB_RX_DESC_DEF;
        port->txq_desc_nb = NETIF_NB_TX_DESC_DEF;
        port->mtu = NETIF_DEFAULT_ETH_MTU;
    }

    if (port->type == PORT_TYPE_BOND_MASTER) {
        assert(port->bond->master.primary);

        /* For some legacy broken DPDK PMD drivers whose flow_type_rss_offloads may not
         * be filled but left zero in dev_info, that will cause the rss reconfiguration
         * in DPDK's bond PMD driver slave_configure() disable the real physical NIC's
         * rss. Since when start the real physical NICs before bond have done a correct
         * configuration of the rss, a workaround is to leave out the rss reconfiguration
         * in bonding if the flow_type_rss_offloads not be filled in PMD driver.
         */
        if (!port->bond->master.primary->dev_info.flow_type_rss_offloads)
            port->dev_conf.rxmode.mq_mode = 0;

        port->dev_conf.rx_adv_conf.rss_conf.rss_hf
            = port->bond->master.primary->dev_conf.rx_adv_conf.rss_conf.rss_hf;
        /* use primary conf for bonding */
        cfg_stream = get_port_conf_stream(port->bond->master.primary->name);
        if (cfg_stream) {
            port->rxq_desc_nb = cfg_stream->rx_desc_nb;
            port->txq_desc_nb = cfg_stream->tx_desc_nb;
            port->mtu = cfg_stream->mtu;
        } else {
            port->rxq_desc_nb = NETIF_NB_RX_DESC_DEF;
            port->txq_desc_nb = NETIF_NB_TX_DESC_DEF;
            port->mtu = NETIF_DEFAULT_ETH_MTU;
        }
    }
    /* enable promicuous mode if configured */
    if (promisc_on) {
        if (cfg_stream && cfg_stream->promisc_mode)
            *promisc_on = 1;
        else
            *promisc_on = 0;
    }
    if (allmulticast) {
        if (cfg_stream && cfg_stream->allmulticast)
            *allmulticast = 1;
        else
            *allmulticast = 0;
    }
}

static int add_bond_slaves(struct netif_port *port)
{
    assert(port->type == PORT_TYPE_BOND_MASTER);

    int ii;
    struct netif_port *slave;

    for (ii = 0; ii < port->bond->master.slave_nb; ii++) {
        slave = port->bond->master.slaves[ii];
        if (rte_eth_bond_slave_add(port->id, slave->id) < 0) {
            RTE_LOG(ERR, NETIF, "%s: fail to add slave %s to %s\n", __func__,
                    slave->name, port->name);
            return EDPVS_DPDKAPIFAIL;
        }
    }

    if (rte_eth_bond_primary_set(port->id, port->bond->master.primary->id) < 0) {
        RTE_LOG(ERR, NETIF, "%s: fail to set slave %s as primary device of %s\n",
                __func__, port->bond->master.primary->name, port->name);
        return EDPVS_DPDKAPIFAIL;
    } else {
        RTE_LOG(INFO, NETIF, "%s: %s primary slave is %s\n",
                __func__, port->name, port->bond->master.primary->name);
    }

    /* Add a MAC address to an internal array of addresses used to enable whitelist
     * * filtering to accept packets only if the destination MAC address matches */
    for (ii = 0; ii < port->bond->master.slave_nb; ii++) {
        slave = port->bond->master.slaves[ii];
        if (rte_eth_dev_mac_addr_add((uint8_t)slave->id, &port->addr, 0) < 0)
            RTE_LOG(ERR, NETIF, "%s: fail to add bonding device %s's mac to %s\n",
                    __func__, port->name, slave->name);
    }

    port->socket = rte_eth_dev_socket_id(port->id);
    port->mbuf_pool = pktmbuf_pool[port->socket];
    port_mtu_set(port);
    rte_eth_dev_info_get(port->id, &port->dev_info);

    return EDPVS_OK;
}

#ifdef CONFIG_DPVS_FDIR
static int config_fdir_conf(struct rte_fdir_conf *fdir_conf)
{
    int shift;

    /* how many mask bits needed? */
    for (shift = 0; (0x1<<shift) < g_slave_lcore_num; shift++)
        ;
    if (shift >= 16)
        return EDPVS_INVAL;

    fdir_conf->mask.dst_port_mask = htons(~((~0x0) << shift));
    fdir_conf->mode = g_fdir_mode;

    return EDPVS_OK;
}
#endif

/*
 * Note: Invoke the function after port is allocated and lcores are configured.
 */
int netif_port_start(struct netif_port *port)
{
    int ii, ret;
    queueid_t qid;
    char promisc_on, allmulticast;
    char buf[512];
    struct rte_eth_txconf txconf;
    struct rte_eth_link link;
    const int wait_link_up_msecs = 30000; //30s
    int buflen = sizeof(buf);

    if (unlikely(NULL == port))
        return EDPVS_INVAL;

    fill_port_config(port, &promisc_on, &allmulticast);
    if (!port->nrxq && !port->ntxq) {
        RTE_LOG(WARNING, NETIF, "%s: no queues to setup for %s\n", __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }

    if (port->nrxq > port->dev_info.max_rx_queues ||
            port->ntxq > port->dev_info.max_tx_queues) {
        rte_exit(EXIT_FAILURE, "%s: %s supports %d rx-queues and %d tx-queues at max, "
                "but %d rx-queues and %d tx-queues are configured.\n", __func__,
                port->name, port->dev_info.max_rx_queues,
                port->dev_info.max_tx_queues, port->nrxq, port->ntxq);
    }

    // device configure
    if ((ret = rte_eth_dev_set_mtu(port->id,port->mtu)) != EDPVS_OK)
        return ret;
#ifdef CONFIG_DPVS_FDIR
    ret = config_fdir_conf(&port->dev_conf.fdir_conf);
    if (ret != EDPVS_OK)
        return ret;
#endif
    if (port->flag & NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
    if (port->flag & NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;
    if (port->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;
    port->dev_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    adapt_device_conf(port->id, &port->dev_conf.rx_adv_conf.rss_conf.rss_hf,
            &port->dev_conf.rxmode.offloads, &port->dev_conf.txmode.offloads);

    ret = rte_eth_dev_configure(port->id, port->nrxq, port->ntxq, &port->dev_conf);
    if (ret < 0 ) {
        RTE_LOG(ERR, NETIF, "%s: fail to config %s\n", __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }

    // setup rx queues
    if (port->nrxq > 0) {
        for (qid = 0; qid < port->nrxq; qid++) {
            ret = rte_eth_rx_queue_setup(port->id, qid, port->rxq_desc_nb,
                    port->socket, NULL, pktmbuf_pool[port->socket]);
            if (ret < 0) {
                RTE_LOG(ERR, NETIF, "%s: fail to config %s:rx-queue-%d\n",
                        __func__, port->name, qid);
                return EDPVS_DPDKAPIFAIL;
            }
        }
    }

    // setup tx queues
    if (port->ntxq > 0) {
        for (qid = 0; qid < port->ntxq; qid++) {
            memcpy(&txconf, &port->dev_info.default_txconf, sizeof(struct rte_eth_txconf));
#if RTE_VERSION < RTE_VERSION_NUM(18, 11, 0, 0)
            if (port->dev_conf.rxmode.jumbo_frame
                    || (port->flag & NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD)
                    || (port->flag & NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD)
                    || (port->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD))
                txconf.txq_flags = 0;
#endif
            txconf.offloads = port->dev_conf.txmode.offloads;
            ret = rte_eth_tx_queue_setup(port->id, qid, port->txq_desc_nb,
                    port->socket, &txconf);
            if (ret < 0) {
                RTE_LOG(ERR, NETIF, "%s: fail to config %s:tx-queue-%d\n",
                        __func__, port->name, qid);
                return EDPVS_DPDKAPIFAIL;
            }
        }
    }

    // add slaves and update stored info for bonding device
    if (port->type == PORT_TYPE_BOND_MASTER) {
        ret = add_bond_slaves(port);
        if (ret != EDPVS_OK)
            return ret;
    }

    netif_print_port_conf(&port->dev_conf, buf, &buflen);
    RTE_LOG(INFO, NETIF, "device %s configuration:\n%s\n", port->name, buf);

    // build port-queue-lcore mapping array
    build_port_queue_lcore_map();

    // start the device
    ret = rte_eth_dev_start(port->id);
    if (ret < 0) {
        RTE_LOG(ERR, NETIF, "%s: fail to start %s\n", __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }

    // wait the device link up
    RTE_LOG(INFO, NETIF, "Waiting for %s link up, be patient ...\n", port->name);
    for (ii = 0; ii < wait_link_up_msecs; ii++) {
        rte_eth_link_get_nowait(port->id, &link);
        if (link.link_status) {
            RTE_LOG(INFO, NETIF, ">> %s: link up - speed %u Mbps - %s\n",
                    port->name, (unsigned)link.link_speed,
                    (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                    "full-duplex" : "half-duplex");
            break;
        }
        rte_delay_ms(1);
    }
    if (!link.link_status) {
        RTE_LOG(ERR, NETIF, "%s: fail to bring up %s\n", __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }

    port->flag |= NETIF_PORT_FLAG_RUNNING;

    // enable promicuous mode if configured
    if (promisc_on) {
        RTE_LOG(INFO, NETIF, "promiscous mode enabled for device %s\n", port->name);
        rte_eth_promiscuous_enable(port->id);
    }

    // enable allmulticast mode if configured
    if (allmulticast) {
        RTE_LOG(INFO, NETIF, "allmulticast enabled for device %s\n", port->name);
        rte_eth_allmulticast_enable(port->id);
    }

     /* update mac addr to netif_port and netif_kni after start */
    if (port->netif_ops->op_update_addr)
        port->netif_ops->op_update_addr(port);

    /* ipv6 default addresses initialization */
    if ((ret = idev_addr_init(port->in_ptr)) != EDPVS_OK) {
        RTE_LOG(WARNING, NETIF, "%s: idev_addr_init failed -- %d(%s)\n",
                __func__, ret, dpvs_strerror(ret));
        return ret;
    }

    /* update rss reta */
    if ((ret = netif_update_rss_reta(port)) != EDPVS_OK)
        RTE_LOG(WARNING, NETIF, "%s: %s update rss reta failed (cause: %s)\n",
                __func__, port->name, dpvs_strerror(ret));

    return EDPVS_OK;
}

int netif_port_stop(struct netif_port *port)
{
    int ret;

    if (unlikely(NULL == port))
        return EDPVS_INVAL;

    if (kni_dev_exist(port))
        kni_del_dev(port);

    rte_eth_dev_stop(port->id);
    ret = rte_eth_dev_set_link_down(port->id);
    if (ret < 0) {
        RTE_LOG(WARNING, NETIF, "%s: fail to set %s link down\n", __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }

    port->flag |= NETIF_PORT_FLAG_STOPPED;
    return EDPVS_OK;
}

int netif_port_register(struct netif_port *port)
{
    struct netif_port *cur;
    int hash, nhash;
    int err;

    if (unlikely(NULL == port))
        return EDPVS_INVAL;

    hash = port_tab_hashkey(port->id);
    list_for_each_entry(cur, &port_tab[hash], list) {
        if (cur->id == port->id || strcmp(cur->name, port->name) == 0) {
            return EDPVS_EXIST;
        }
    }

    nhash = port_ntab_hashkey(port->name, sizeof(port->name));
    list_for_each_entry(cur, &port_ntab[hash], nlist) {
        if (cur->id == port->id || strcmp(cur->name, port->name) == 0) {
            return EDPVS_EXIST;
        }
    }

    list_add_tail(&port->list, &port_tab[hash]);
    list_add_tail(&port->nlist, &port_ntab[nhash]);
    g_nports++;

    if (port->netif_ops->op_init) {
        err = port->netif_ops->op_init(port);
        if (err != EDPVS_OK) {
            netif_port_unregister(port);
            return err;
        }
    }

    return EDPVS_OK;
}

int netif_port_unregister(struct netif_port *port)
{
    struct netif_port *cur, *next;
    int ret1, ret2, hash, nhash;
    if (unlikely(NULL == port))
        return EDPVS_INVAL;
    ret1 = ret2 = EDPVS_NOTEXIST;

    hash = port_tab_hashkey(port->id);
    list_for_each_entry_safe(cur, next, &port_tab[hash], list) {
        if (cur->id == port->id || strcmp(cur->name, port->name) == 0) {
            list_del_init(&cur->list);
            ret1 = EDPVS_OK;
            break;
        }
    }

    nhash = port_ntab_hashkey(port->name, sizeof(port->name));
    list_for_each_entry_safe(cur, next, &port_ntab[nhash], nlist) {
        if (cur->id == port->id || strcmp(cur->name, port->name) == 0) {
            list_del_init(&cur->nlist);
            ret2 = EDPVS_OK;
            break;
        }
    }

    if (ret1 != EDPVS_OK || ret2 != EDPVS_OK)
        return EDPVS_NOTEXIST;

    g_nports--;
    return EDPVS_OK;
}

/* FIXME: port_id in cfgfile file is not consistent with correspondings in program, if
 * port id not sequentially resided in cfgfile. If so, fill_bonding_device is problematic. */
static int relate_bonding_device(void)
{
    int i;
    struct bond_conf_stream *bond_conf;
    struct netif_port *mport, *sport;

    list_for_each_entry_reverse(bond_conf, &bond_list, bond_list_node) {
        mport = netif_port_get_by_name(bond_conf->name);
        if (!mport) {
            RTE_LOG(ERR, NETIF, "%s: bonding master device %s not found\n",
                    __func__, bond_conf->name);
            return EDPVS_NOTEXIST;
        }
        assert(mport->type == PORT_TYPE_BOND_MASTER);
        mport->bond->master.mode = bond_conf->mode;
        for (i = 0; bond_conf->slaves[i][0] && i < NETIF_MAX_BOND_SLAVES; i++) {
            sport = netif_port_get_by_name(bond_conf->slaves[i]);
            if (!sport) {
                RTE_LOG(ERR, NETIF, "%s: bonding slave device %s not found\n",
                        __func__, bond_conf->slaves[i]);
                return EDPVS_NOTEXIST;
            }
            if (sport->bond->slave.master) {
                RTE_LOG(ERR, NETIF, "%s: device %s is slave of %s already\n",
                        __func__, bond_conf->slaves[i], sport->bond->slave.master->name);
                return EDPVS_EXIST;
            }
            mport->bond->master.slaves[i] = sport;
            if (!strcmp(bond_conf->slaves[i], bond_conf->primary)) {
                mport->bond->master.primary = sport;
                rte_ether_addr_copy(&sport->addr, &mport->addr);  /* use primary slave's macaddr for bonding */
            }
            assert(sport->type == PORT_TYPE_GENERAL);
            if (sport->socket != mport->socket) {
                /* FIXME: all slaves share the same socket with master, otherwise kernel crash */
                RTE_LOG(WARNING, NETIF, "%s: %s is created on numa node %d, while its slave %s"
                        " is on numa node %d\n", __func__, mport->name, mport->socket,
                        sport->name, sport->socket);
                sport->socket = mport->socket;
            }
            sport->type = PORT_TYPE_BOND_SLAVE;
            sport->bond->slave.master = mport;
            sport->in_ptr->flags |= IDEV_F_NO_ROUTE;
        }
        mport->bond->master.slave_nb = i;
    }
    return EDPVS_OK;
}

static struct rte_eth_conf default_port_conf = {
    .rxmode = {
        .mq_mode        = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .offloads = DEV_RX_OFFLOAD_IPV4_CKSUM,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf  = /*ETH_RSS_IP*/ ETH_RSS_TCP,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
#ifdef CONFIG_DPVS_FDIR
    .fdir_conf = {
        .mode    = RTE_FDIR_MODE_PERFECT, /* maybe changed by config file */
        .pballoc = RTE_FDIR_PBALLOC_64K,
        .status  = RTE_FDIR_REPORT_STATUS,
        .mask    = {
            .ipv4_mask  = {
                .dst_ip = 0xFFFFFFFF,
            },
            .ipv6_mask  = {
                .dst_ip = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
            },
            /* to be changed according to slave lcore number in use */
            .dst_port_mask = 0x0700,
        },
        .drop_queue = 127,
        .flex_conf  = {
            .nb_payloads    = 0,
            .nb_flexmasks   = 0,
        },
    },
#endif
};

int netif_print_port_conf(const struct rte_eth_conf *port_conf, char *buf, int *len)
{
    char tbuf1[256], tbuf2[128];
    if (unlikely(NULL == buf) || 0 == len)
        return EDPVS_INVAL;
    if (port_conf == NULL)
        port_conf = &default_port_conf;

    memset(buf, 0, *len);
    if (port_conf->rxmode.mq_mode == ETH_MQ_RX_RSS) {
        memset(tbuf2, 0, sizeof(tbuf2));
        if (port_conf->rx_adv_conf.rss_conf.rss_hf) {
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & ETH_RSS_IP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_IP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & ETH_RSS_TCP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_TCP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & ETH_RSS_UDP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_UDP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & ETH_RSS_SCTP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_SCTP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & ETH_RSS_L2_PAYLOAD)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_L2_PAYLOAD ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & ETH_RSS_PORT)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_PORT ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & ETH_RSS_TUNNEL)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_TUNNEL ");
        } else {
            snprintf(tbuf2, sizeof(tbuf2), "Inhibited");
        }

        memset(tbuf1, 0, sizeof(tbuf1));
        snprintf(tbuf1, sizeof(tbuf1), "RSS: %s\n", tbuf2);
        if (*len - strlen(buf) - 1 < strlen(tbuf1)) {
            RTE_LOG(WARNING, NETIF, "[%s] no enough buf\n", __func__);
            return EDPVS_INVAL;
        }
        strncat(buf, tbuf1, *len - strlen(buf) - 1);
    }

    *len = strlen(buf);
    return EDPVS_OK;
}

static char *find_conf_kni_name(portid_t id)
{
    struct port_conf_stream *port_cfg;
    struct bond_conf_stream *bond_cfg;

    list_for_each_entry(port_cfg, &port_list, port_list_node) {
        if (port_cfg->port_id == id)
            return port_cfg->kni_name;
    }

    list_for_each_entry(bond_cfg, &bond_list, bond_list_node) {
        if (bond_cfg->port_id == id)
            return bond_cfg->kni_name;
    }

    return NULL;
}

static void dpdk_port_setup(struct netif_port *dev)
{
    dev->type      = PORT_TYPE_GENERAL;
    dev->netif_ops = &dpdk_netif_ops;
    dev->socket    = rte_eth_dev_socket_id(dev->id);
    dev->dev_conf  = default_port_conf;
    dev->bond      = (union netif_bond *)(dev + 1);

    rte_eth_macaddr_get(dev->id, &dev->addr);
    rte_eth_dev_get_mtu(dev->id, &dev->mtu);
    rte_eth_dev_info_get(dev->id, &dev->dev_info);
    setup_dev_of_flags(dev);
}

static void bond_port_setup(struct netif_port *dev)
{
    dev->type      = PORT_TYPE_BOND_MASTER;
    dev->netif_ops = &bond_netif_ops;
    dev->socket    = rte_eth_dev_socket_id(dev->id);
    dev->dev_conf  = default_port_conf;
    dev->bond      = (union netif_bond *)(dev + 1);

    rte_eth_macaddr_get(dev->id, &dev->addr);
    rte_eth_dev_get_mtu(dev->id, &dev->mtu);
    rte_eth_dev_info_get(dev->id, &dev->dev_info);
    setup_dev_of_flags(dev);
}

/* Allocate and register all DPDK ports available */
static void netif_port_init(void)
{
    int nports, nports_cfg;
    portid_t pid;
    struct netif_port *port;
    char *kni_name;
    char ifname[IFNAMSIZ];

    nports = dpvs_rte_eth_dev_count();
    if (nports <= 0)
        rte_exit(EXIT_FAILURE, "No dpdk ports found!\n"
                "Possibly nic or driver is not dpdk-compatible.\n");

    nports_cfg = list_elems(&port_list) + list_elems(&bond_list);
    if (nports_cfg < nports)
        rte_exit(EXIT_FAILURE, "ports in DPDK RTE (%d) != ports in dpvs.conf(%d)\n",
                nports, nports_cfg);

    port_tab_init();
    port_ntab_init();

    kni_init();

    for (pid = 0; pid < nports; pid++) {
        if (port_name_alloc(pid, ifname, sizeof(ifname)) != EDPVS_OK)
            rte_exit(EXIT_FAILURE, "Port name allocation failed, exiting...\n");

        /* queue number will be filled on device start */
        port = NULL;
        if (is_physical_port(pid))
            port = netif_alloc(pid, sizeof(union netif_bond), ifname, 0, 0, dpdk_port_setup);
        else if (is_bond_port(pid))
            port = netif_alloc(pid, sizeof(union netif_bond), ifname, 0, 0, bond_port_setup);
        if (!port)
            rte_exit(EXIT_FAILURE, "Port allocation failed, exiting...\n");

        if (netif_port_register(port) < 0)
            rte_exit(EXIT_FAILURE, "Port registration failed, exiting...\n");
    }

    if (relate_bonding_device() < 0)
        rte_exit(EXIT_FAILURE, "relate_bonding_device fail, exiting...\n");

    /* auto generate KNI device for all build-in
     * phy ports and bonding master ports, but not bonding slaves */
    for (pid = 0; pid < nports; pid++) {
        port = netif_port_get(pid);
        assert(port);

        if (port->type == PORT_TYPE_BOND_SLAVE)
            continue;

        kni_name = find_conf_kni_name(pid);

        /* it's ok if no KNI name (kni_name is NULL) */
        if (kni_add_dev(port, kni_name) < 0)
            rte_exit(EXIT_FAILURE, "add KNI port fail, exiting...\n");
    }
}

/******************************************* module ***********************************************/

/*! \brief obtain DPDK bond device name
 *
 *  obtain new DPDK bond device name to fit with DPDK 17.11
 *
 * \param dst obtained new DPDK device name
 * \param ori original bond device name from config
 * \param size device name max length
 * \return EDPVS_OK if success
 */
static int obtain_dpdk_bond_name(char *dst, const char *ori, size_t size)
{
    char str[IFNAMSIZ];
    unsigned num;

    if (!ori || sscanf(ori, "%[_a-zA-Z]%u", str, &num) != 2)
        return EDPVS_INVAL;

    /*
     * DPDK need bonding device name start with "net_bonding"
     * to match the driver.
     */
    snprintf(dst, size, "net_bonding%u", num);

    return EDPVS_OK;
}

/*
 * netif_virtual_devices_add must be called before lcore_init and port_init,
 * so it's recommended to call this function immediately after cfgfile_init.
 */
int netif_vdevs_add(void)
{
    int ret;
    struct bond_conf_stream *bond_cfg;

#ifdef NETIF_BONDING_DEBUG
    int ii, len = 0;
    char slavenames[NETIF_MAX_BOND_SLAVES*IFNAMSIZ];
    list_for_each_entry_reverse(bond_cfg, &bond_list, bond_list_node) {
        for (ii = 0; ii < NETIF_MAX_BOND_SLAVES && bond_cfg->slaves[ii][0]; ii++) {
            ret = snprintf(&slavenames[len], sizeof(slavenames)-len-1, "%s ", bond_cfg->slaves[ii]);
            if (ret >= 0)
                len += ret;
        }
        RTE_LOG(DEBUG, NETIF, "Add bonding device \"%s\""
                "\n\tmode: %d"
                "\n\tprimary: %s"
                "\n\tnuma_node: %d"
                "\n\tslaves: %s\n",
                bond_cfg->name,
                bond_cfg->mode,
                bond_cfg->primary[0] ? bond_cfg->primary : ii > 0 ? bond_cfg->slaves[0] : "",
                bond_cfg->numa_node,
                slavenames);
    }
#endif

    /* set phy_pid_end/bond_pid_base before create bonding device */
    phy_pid_end = dpvs_rte_eth_dev_count();
    port_id_end = max(port_id_end, phy_pid_end);
    if (!list_empty(&bond_list))
        bond_pid_base = phy_pid_end;

    list_for_each_entry_reverse(bond_cfg, &bond_list, bond_list_node) {
        char bondname[IFNAMSIZ] = {'\0'};

        if (!bond_cfg->slaves[0][0]) {
            RTE_LOG(WARNING, NETIF, "%s: no slaves configured for %s, skip ...\n",
                    __func__, bond_cfg->name);
            return EDPVS_INVAL;
        }

        /* use the first slave as primary if not configured */
        if (!bond_cfg->primary[0]) {
            RTE_LOG(INFO, NETIF, "%s: %s primary slave is not configured, using %s\n",
                    __func__, bond_cfg->name, bond_cfg->slaves[0]);
            strncpy(bond_cfg->primary, bond_cfg->slaves[0], sizeof(bond_cfg->primary));
        }

        ret = obtain_dpdk_bond_name(bondname, bond_cfg->name, IFNAMSIZ);
        if (ret != EDPVS_OK) {
            RTE_LOG(ERR, NETIF, "%s: invalid bonding device name in config file %s\n",
                    __func__, bond_cfg->name);
            return EDPVS_INVAL;
        }

        /* Note that all slaves' numa nodes should be the same as the one of bonding,
         * otherwise the bonding and slaves cannot link up. Nevertheless, if you are
         * to use slaves from different numa nodes, the dpdk patch
         *      [bonding: allow slaves from different numa nodes]
         * should be applied, which may cause negative influence on performance. */
        ret = rte_eth_bond_create(bondname, bond_cfg->mode, bond_cfg->numa_node);
        if (ret < 0) {
            RTE_LOG(ERR, NETIF, "%s: fail to create bonding device %s: mode=%d, numa_node=%d\n",
                    __func__, bond_cfg->name, bond_cfg->mode, bond_cfg->numa_node);
            return EDPVS_CALLBACKFAIL;
        }
        bond_cfg->port_id = ret; /* relate port_id with port_name, used by port_name_alloc */
        RTE_LOG(INFO, NETIF, "created bondig device %s: mode=%d, primary=%s, numa_node=%d\n",
                bond_cfg->name, bond_cfg->mode, bond_cfg->primary, bond_cfg->numa_node);

        if (bond_cfg->mode == BONDING_MODE_8023AD && bond_cfg->options.dedicated_queues_enable) {
            if (rte_eth_bond_8023ad_dedicated_queues_enable(bond_cfg->port_id)) {
                RTE_LOG(INFO, NETIF, "%s: bonding mode4 dedicated queues enable failed!\n", __func__);
            }
        }
    }

    if (!list_empty(&bond_list)) {
        bond_pid_end = dpvs_rte_eth_dev_count();
        port_id_end = max(port_id_end, bond_pid_end);
        RTE_LOG(INFO, NETIF, "bonding device port id range: [%d, %d)\n", bond_pid_base, bond_pid_end);
    }

    return EDPVS_OK;
}

int netif_init(void)
{
    netif_pktmbuf_pool_init();
    netif_arp_ring_init();
    netif_pkt_type_tab_init();
    netif_port_init();
    netif_lcore_init();

    g_master_lcore_id = rte_get_main_lcore();
    netif_get_slave_lcores(&g_slave_lcore_num, &g_slave_lcore_mask);
    netif_get_isol_rx_lcores(&g_isol_rx_lcore_num, &g_isol_rx_lcore_mask);

    return EDPVS_OK;
}

int netif_term(void)
{
    netif_lcore_cleanup();
    netif_cfgfile_term();
    return EDPVS_OK;
}


/************************************ Ctrl Plane ***************************************/

static int get_lcore_mask(void **out, size_t *out_len)
{
    assert(out && out_len);

    netif_lcore_mask_get_t *get;

    get = rte_zmalloc(NULL, sizeof(netif_lcore_mask_get_t),
            RTE_CACHE_LINE_SIZE);
    if (unlikely (NULL == get))
        return EDPVS_NOMEM;

    get->master_lcore_id = g_master_lcore_id;
    get->kni_lcore_id = g_kni_lcore_id;
    get->slave_lcore_num = g_slave_lcore_num;
    get->slave_lcore_mask = g_slave_lcore_mask;
    get->isol_rx_lcore_num = g_isol_rx_lcore_num;
    get->isol_rx_lcore_mask = g_isol_rx_lcore_mask;

    *out = get;
    *out_len = sizeof(netif_lcore_mask_get_t);

    return EDPVS_OK;
}

static int get_lcore_basic(lcoreid_t cid, void **out, size_t *out_len)
{
    assert(out && out_len);

    netif_lcore_basic_get_t *get;
    int err, len;
    char buf[NETIF_CTRL_BUFFER_LEN];

    len = NETIF_CTRL_BUFFER_LEN;
    if (is_isol_rxq_lcore(cid))
        err = netif_print_isol_lcore_conf(cid, buf, &len, false);
    else
        err = netif_print_lcore_queue_conf(cid, buf, &len, false);

    if (unlikely(!(EDPVS_OK == err)))
        return err;
    assert(len < NETIF_CTRL_BUFFER_LEN);

    get = rte_zmalloc(NULL, sizeof(netif_lcore_basic_get_t) + len,
            RTE_CACHE_LINE_SIZE);
    if (unlikely(NULL == get))
        return EDPVS_NOMEM;

    get->lcore_id = cid;
    get->socket_id = rte_lcore_to_socket_id(cid);
    get->queue_data_len = len;
    memcpy(&get->queue_data[0], buf, len);

    *out = get;
    *out_len = sizeof(netif_lcore_basic_get_t) + len;

    return EDPVS_OK;
}

static int lcore_stats_msg_cb(struct dpvs_msg *msg)
{
    void *reply_data;

    if (unlikely(!msg || msg->type != MSG_TYPE_NETIF_LCORE_STATS ||
                msg->mode != DPVS_MSG_UNICAST))
        return EDPVS_INVAL;

    reply_data = msg_reply_alloc(sizeof(struct netif_lcore_stats));
    if (unlikely(!reply_data))
        return EDPVS_NOMEM;

    netif_copy_lcore_stats(reply_data);

    msg->reply.len = sizeof(struct netif_lcore_stats);
    msg->reply.data = reply_data;

    return EDPVS_OK;
}

static inline int lcore_stats_msg_init(void)
{
    int ii, err;
    struct dpvs_msg_type lcore_stats_msg_type = {
        .type = MSG_TYPE_NETIF_LCORE_STATS,
        .mode = DPVS_MSG_UNICAST,
        .prio = MSG_PRIO_LOW,
        .unicast_msg_cb = lcore_stats_msg_cb,
        .multicast_msg_cb = NULL,
    };

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if ((ii == g_master_lcore_id) || (g_slave_lcore_mask & (1L << ii))) {
            lcore_stats_msg_type.cid = ii;
            err = msg_type_register(&lcore_stats_msg_type);
            if (EDPVS_OK != err) {
                RTE_LOG(WARNING, NETIF, "[%s] fail to register NETIF_LCORE_STATS msg-type "
                        "on lcore%d: %s\n", __func__, ii, dpvs_strerror(err));
                return err;
            }
        }
    }

    return EDPVS_OK;
}

static inline int lcore_stats_msg_term(void)
{
    int ii, err;
    struct dpvs_msg_type lcore_stats_msg_type = {
        .type = MSG_TYPE_NETIF_LCORE_STATS,
        .mode = DPVS_MSG_UNICAST,
        .prio = MSG_PRIO_LOW,
        .unicast_msg_cb = lcore_stats_msg_cb,
        .multicast_msg_cb = NULL,
    };

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if ((ii == g_master_lcore_id) || (g_slave_lcore_mask & (1L << ii))) {
            lcore_stats_msg_type.cid = ii;
            err = msg_type_unregister(&lcore_stats_msg_type);
            if (EDPVS_OK != err) {
                RTE_LOG(WARNING, NETIF, "[%s] fail to unregister NETIF_LCORE_STATS msg-type "
                        "on lcore%d: %s\n", __func__, ii, dpvs_strerror(err));
                return err;
            }
        }
    }

    return EDPVS_OK;
}

void netif_update_worker_loop_cnt(void)
{
    lcore_stats[rte_lcore_id()].lcore_loop++;
}

static int get_lcore_stats(lcoreid_t cid, void **out, size_t *out_len)
{
    assert(out && out_len);

    netif_lcore_stats_get_t *get;
    struct netif_lcore_stats stats;

    get = rte_zmalloc(NULL, sizeof(struct netif_lcore_stats_get),
            RTE_CACHE_LINE_SIZE);
    if (unlikely(!get))
        return EDPVS_NOMEM;

    if (is_isol_rxq_lcore(cid) || is_kni_lcore(cid)) {
        /* use write lock to ensure data safety */
        memcpy(&stats, &lcore_stats[cid], sizeof(stats));
    } else {
        int err;
        struct dpvs_msg *pmsg;
        struct dpvs_msg_reply *reply;

        pmsg = msg_make(MSG_TYPE_NETIF_LCORE_STATS, 0, DPVS_MSG_UNICAST,
                rte_lcore_id(), 0, NULL);
        if (unlikely(!pmsg)) {
            rte_free(get);
            return EDPVS_NOMEM;
        }

        err = msg_send(pmsg, cid, 0, &reply);
        if (EDPVS_OK != err) {
            msg_destroy(&pmsg);
            rte_free(get);
            return err;
        }

        assert(reply->len == sizeof(struct netif_lcore_stats));
        assert(reply->data);
        rte_memcpy(&stats, reply->data, sizeof(stats));

        msg_destroy(&pmsg);
    }

    get->lcore_id = cid;
    get->lcore_loop = stats.lcore_loop;
    get->pktburst = stats.pktburst;
    get->zpktburst = stats.zpktburst;
    get->fpktburst = stats.fpktburst;
    get->z2hpktburst = stats.z2hpktburst;
    get->h2fpktburst = stats.h2fpktburst;
    get->ipackets = stats.ipackets;
    get->ibytes = stats.ibytes;
    get->opackets = stats.opackets;
    get->obytes = stats.obytes;
    get->dropped = stats.dropped;

    *out = get;
    *out_len = sizeof(netif_lcore_stats_get_t);

    return EDPVS_OK;
}

static int get_port_list(void **out, size_t *out_len)
{
    int i, cnt = 0;
    size_t len;
    struct netif_port *port;
    netif_nic_list_get_t *get;

    assert(out && out_len);

    len = sizeof(netif_nic_list_get_t) + g_nports * sizeof(struct port_id_name);
    get = rte_zmalloc(NULL, len, RTE_CACHE_LINE_SIZE);
    if (unlikely(!get))
        return EDPVS_NOMEM;

    get->phy_pid_base = phy_pid_base;
    get->phy_pid_end = phy_pid_end;
    get->bond_pid_base = bond_pid_base;
    get->bond_pid_end = bond_pid_end;

    for (i = 0; i < NETIF_PORT_TABLE_BUCKETS; i++) {
        list_for_each_entry(port, &port_tab[i], list) {
            get->idname[cnt].id = port->id;
            snprintf(get->idname[cnt].name, sizeof(get->idname[cnt].name),
                    "%s", port->name);
            cnt++;
            if (cnt > g_nports) {
                RTE_LOG(ERR, NETIF, "%s: Too many ports in port_tab than expected!\n",
                        __func__);
                break;
            }
        }
    }

    get->nic_num = cnt;

    *out = get;
    *out_len = len;

    return EDPVS_OK;
}

static int get_port_basic(struct netif_port *port, void **out, size_t *out_len)
{
    struct rte_eth_link link;
    netif_nic_basic_get_t *get;
    bool promisc;
    bool allmulticast;
    int err;

    get = rte_zmalloc(NULL, sizeof(netif_nic_basic_get_t),
            RTE_CACHE_LINE_SIZE);
    if (unlikely(!get))
        return EDPVS_NOMEM;

    err = netif_get_link(port, &link);
    if (err != EDPVS_OK) {
        rte_free(get);
        return err;
    }

    get->port_id = port->id;
    strncpy(get->name, port->name, sizeof(get->name));
    get->nrxq = port->nrxq;
    get->ntxq = port->ntxq;
    rte_ether_format_addr(get->addr, sizeof(get->addr), &port->addr);

    get->socket_id = port->socket;
    get->mtu = port->mtu;

    get->link_speed = link.link_speed;

    switch (link.link_status) {
        case ETH_LINK_UP:
            snprintf(get->link_status, sizeof(get->link_status), "%s", "UP");
            break;
        case ETH_LINK_DOWN:
            snprintf(get->link_status, sizeof(get->link_status), "%s", "DOWN");
            break;
    }

    switch (link.link_duplex) {
        case ETH_LINK_HALF_DUPLEX:
            snprintf(get->link_duplex, sizeof(get->link_duplex), "%s", "half-duplex");
            break;
        case ETH_LINK_FULL_DUPLEX:
            snprintf(get->link_duplex, sizeof(get->link_duplex), "%s", "full-duplex");
            break;
    }

    switch (link.link_autoneg) {
        case ETH_LINK_FIXED:
            snprintf(get->link_autoneg, sizeof(get->link_autoneg), "%s", "fixed-nego");
            break;
        case ETH_LINK_AUTONEG:
            snprintf(get->link_autoneg, sizeof(get->link_autoneg), "%s", "auto-nego");
            break;
    }

    err = netif_get_promisc(port, &promisc);
    if (err != EDPVS_OK) {
        rte_free(get);
        return err;
    }
    get->promisc = promisc ? 1 : 0;

    err = netif_get_allmulticast(port, &allmulticast);
    if (err != EDPVS_OK) {
        rte_free(get);
        return err;
    }
    get->allmulticast = allmulticast ? 1 : 0;

    if (port->flag & NETIF_PORT_FLAG_FORWARD2KNI)
        get->fwd2kni = 1;
    if (port->flag & NETIF_PORT_FLAG_TC_EGRESS)
        get->tc_egress= 1;
    if (port->flag & NETIF_PORT_FLAG_TC_INGRESS)
        get->tc_ingress = 1;
    if (port->flag & NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD)
        get->ol_rx_ip_csum = 1;
    if (port->flag & NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD)
        get->ol_tx_ip_csum = 1;
    if (port->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD)
        get->ol_tx_tcp_csum = 1;
    if (port->flag & NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD)
        get->ol_tx_udp_csum = 1;
    if (port->flag & NETIF_PORT_FLAG_LLDP)
        get->lldp = 1;

    *out = get;
    *out_len = sizeof(netif_nic_basic_get_t);

    return EDPVS_OK;
}

static inline void copy_dev_info(struct netif_nic_dev_get *get,
        const struct rte_eth_dev_info *dev_info)
{
    const struct rte_pci_device *pci_dev = NULL;
#if RTE_VERSION < RTE_VERSION_NUM(18, 11, 0, 0)
    pci_dev = dev_info->pci_dev;
#else
    if (dev_info->device) {
        const struct rte_bus *bus = NULL;
        bus = rte_bus_find_by_device(dev_info->device);
        if (bus && !strcmp(bus->name, "pci")) {
            pci_dev = RTE_DEV_TO_PCI(dev_info->device);
        }
    }
#endif
    if (pci_dev)
        snprintf(get->pci_addr, sizeof(get->pci_addr), "%04x:%02x:%02x:%0x",
                 pci_dev->addr.domain, pci_dev->addr.bus,
                 pci_dev->addr.devid, pci_dev->addr.function);
    if (dev_info->driver_name)
        strncpy(get->driver_name, dev_info->driver_name, sizeof(get->driver_name));
    get->if_index = dev_info->if_index;
    get->min_rx_bufsize = dev_info->min_rx_bufsize;
    get->max_rx_pktlen = dev_info->max_rx_pktlen;
    get->max_rx_queues = dev_info->max_rx_queues;
    get->max_tx_queues = dev_info->max_tx_queues;
    get->max_mac_addrs = dev_info->max_mac_addrs;
    get->max_vfs = dev_info->max_vfs;
    get->max_vmdq_pools = dev_info->max_vmdq_pools;
    get->rx_offload_capa = dev_info->rx_offload_capa;
    get->tx_offload_capa = dev_info->tx_offload_capa;
    get->reta_size = dev_info->reta_size;
    get->hash_key_size = dev_info->hash_key_size;
    get->flow_type_rss_offloads = dev_info->flow_type_rss_offloads;
    get->vmdq_queue_base = dev_info->vmdq_queue_base;
    get->vmdq_queue_num = dev_info->vmdq_queue_num;
    get->vmdq_pool_base = dev_info->vmdq_pool_base;
    get->rx_desc_lim_nb_max = dev_info->rx_desc_lim.nb_max;
    get->rx_desc_lim_nb_min = dev_info->rx_desc_lim.nb_min;
    get->rx_desc_lim_nb_align = dev_info->rx_desc_lim.nb_align;
    get->tx_desc_lim_nb_max = dev_info->tx_desc_lim.nb_max;
    get->tx_desc_lim_nb_min = dev_info->tx_desc_lim.nb_min;
    get->tx_desc_lim_nb_align = dev_info->tx_desc_lim.nb_align;
    get->speed_capa = dev_info->speed_capa;
}

static int get_port_ext_info(struct netif_port *port, void **out, size_t *out_len)
{
    assert(out || out_len);

    struct rte_eth_dev_info dev_info = { 0 };
    netif_nic_ext_get_t *get, *new;
    char ctrlbuf[NETIF_CTRL_BUFFER_LEN];
    int len, naddr, err;
    size_t offset = 0;

    get = rte_zmalloc(NULL, sizeof(netif_nic_ext_get_t), 0);
    if (unlikely(!get))
        return EDPVS_NOMEM;

    get->port_id = port->id;

    /* dev info */
    if (is_physical_port( port->id) || is_bond_port(port->id)) {
        rte_eth_dev_info_get(port->id, &dev_info);
        copy_dev_info(&get->dev_info, &dev_info);
    }

    /* cfg_queues */
    if (port->type == PORT_TYPE_GENERAL ||
        port->type == PORT_TYPE_BOND_MASTER) {
        len = NETIF_CTRL_BUFFER_LEN;
        err = netif_print_lcore_conf(ctrlbuf, &len, false, port->id);
        if (unlikely(EDPVS_OK != err))
            goto errout;

        new = rte_realloc(get, sizeof(netif_nic_ext_get_t) + len + 1, 0);
        if (unlikely(!new)) {
            err = EDPVS_NOMEM;
            goto errout;
        }
        get = new;

        get->cfg_queues.data_offset = offset;
        get->cfg_queues.data_len = len;
        memcpy(&get->data[offset], ctrlbuf, len);
        offset += len;
        get->data[offset] = '\0';
        offset++;
    }

    /* mc_list */
    len = NETIF_CTRL_BUFFER_LEN;
    err = netif_mc_print(port, ctrlbuf, &len, &naddr);
    if (unlikely(EDPVS_OK != err))
        goto errout;

    new = rte_realloc(get, sizeof(netif_nic_ext_get_t) + offset + len + 1, 0);
    if (unlikely(!new)) {
        err = EDPVS_NOMEM;
        goto errout;
    }
    get = new;

    get->mc_list.data_offset = offset;
    get->mc_list.data_len = len;
    get->mc_list.naddr = naddr;
    memcpy(&get->data[offset], ctrlbuf, len);
    offset += len;

    get->data[offset] = '\0';
    offset++;

    get->datalen = offset;

    *out = get;
    *out_len = sizeof(netif_nic_ext_get_t) + get->datalen;

    return EDPVS_OK;

errout:
    rte_free(get);
    return err;
}

static inline void copy_port_stats(netif_nic_stats_get_t *get,
        const struct rte_eth_stats *stats)
{
    get->ipackets = stats->ipackets;
    get->opackets = stats->opackets;
    get->ibytes = stats->ibytes;
    get->obytes = stats->obytes;
    get->imissed = stats->imissed;
    get->ierrors = stats->ierrors;
    get->oerrors = stats->oerrors;
    get->rx_nombuf = stats->rx_nombuf;
    memcpy(&get->q_ipackets, &stats->q_ipackets, sizeof(stats->q_ipackets));
    memcpy(&get->q_opackets, &stats->q_opackets, sizeof(stats->q_opackets));
    memcpy(&get->q_ibytes, &stats->q_ibytes, sizeof(stats->q_ibytes));
    memcpy(&get->q_obytes, &stats->q_obytes, sizeof(stats->q_obytes));
    memcpy(&get->q_errors, &stats->q_errors, sizeof(stats->q_errors));
}

static int get_port_stats(struct netif_port *port, void **out, size_t *out_len)
{
    assert(out && out_len);

    int err;
    struct rte_eth_stats stats;
    netif_nic_stats_get_t *get;

    err = netif_get_stats(port, &stats);
    if (err != EDPVS_OK)
        return err;

    get = rte_zmalloc(NULL, sizeof(netif_nic_stats_get_t),
            RTE_CACHE_LINE_SIZE);
    if (unlikely(!get))
        return EDPVS_NOMEM;

    get->port_id = port->id;
    get->mbuf_avail = rte_mempool_avail_count(port->mbuf_pool);
    get->mbuf_inuse = rte_mempool_in_use_count(port->mbuf_pool);

    copy_port_stats(get, &stats);

    *out = get;
    *out_len = sizeof(netif_nic_stats_get_t);

    return EDPVS_OK;
}

static int get_port_xstats(struct netif_port *port, void **out, size_t *out_len)
{
    int err;
    assert(out && out_len);

    netif_nic_xstats_get_t *get;
    err = netif_get_xstats(port, &get);
    if (err != EDPVS_OK) {
        if (err == EDPVS_NOTSUPP)
            return EDPVS_OK;
        return err;
    }

    *out = get;
    *out_len = sizeof(netif_nic_xstats_get_t) + get->nentries * sizeof(struct netif_nic_xstats_entry);

    return EDPVS_OK;
}

static int get_bond_status(struct netif_port *port, void **out, size_t *out_len)
{
    bool is_active;
    int i, j, xmit_policy;
    portid_t primary;
    uint16_t slaves[NETIF_MAX_BOND_SLAVES], actives[NETIF_MAX_BOND_SLAVES];
    struct netif_port *sport, *mport = port;
    netif_bond_status_get_t *get;
    assert(out && out_len);

    if (!mport)
        return EDPVS_NOTEXIST;
    if (mport->type != PORT_TYPE_BOND_MASTER)
        return EDPVS_INVAL;

    get = rte_zmalloc(NULL, sizeof(netif_bond_status_get_t),
            RTE_CACHE_LINE_SIZE);
    if (unlikely(!get))
        return EDPVS_NOMEM;
    get->mode = rte_eth_bond_mode_get(port->id);

    primary = rte_eth_bond_primary_get(port->id);
    get->slave_nb = rte_eth_bond_slaves_get(port->id,
            slaves, NETIF_MAX_BOND_SLAVES);
    get->active_nb = rte_eth_bond_active_slaves_get(port->id,
            actives, NETIF_MAX_BOND_SLAVES);
    for (i = 0; i < get->slave_nb; i++) {
        is_active = false;
        for (j = 0; j < get->active_nb; j++) {
            if (actives[j] == slaves[i]) {
                is_active = true;
                break;
            }
        }
        sport = netif_port_get(slaves[i]);
        snprintf(get->slaves[i].name, sizeof(get->slaves[i].name),
                "%s", sport ? sport->name : "UNKOWN");
        if (is_active)
            get->slaves[i].is_active = 1;
        if (slaves[i] == primary)
            get->slaves[i].is_primary = 1;
        rte_ether_format_addr(&get->slaves[i].macaddr[0], sizeof(get->slaves[i].macaddr) - 1, &sport->addr);
    }

    rte_ether_format_addr(get->macaddr, sizeof(get->macaddr), &mport->addr);

    xmit_policy = rte_eth_bond_xmit_policy_get(port->id);
    switch (xmit_policy) {
    case BALANCE_XMIT_POLICY_LAYER2:
        snprintf(get->xmit_policy, sizeof(get->xmit_policy), "LAYER2");
        break;
    case BALANCE_XMIT_POLICY_LAYER23:
        snprintf(get->xmit_policy, sizeof(get->xmit_policy), "LAYER23");
        break;
    case BALANCE_XMIT_POLICY_LAYER34:
        snprintf(get->xmit_policy, sizeof(get->xmit_policy), "LAYER34");
        break;
    default:
        snprintf(get->xmit_policy, sizeof(get->xmit_policy), "UNKOWN");
    }

    get->link_monitor_interval = rte_eth_bond_link_monitoring_get(port->id);
    get->link_down_prop_delay = rte_eth_bond_link_down_prop_delay_get(port->id);
    get->link_up_prop_delay = rte_eth_bond_link_up_prop_delay_get(port->id);

    *out = get;
    *out_len = sizeof(netif_bond_status_get_t);
    return EDPVS_OK;
}

static int netif_sockopt_get(sockoptid_t opt, const void *in, size_t inlen,
                             void **out, size_t *outlen)
{
    int ret = EDPVS_OK;
    lcoreid_t cid;
    char *name;
    struct netif_port *port;

    if (!out || !outlen)
        return EDPVS_INVAL;
    *out = NULL;
    *outlen = 0;

    switch (opt) {
        case SOCKOPT_NETIF_GET_LCORE_MASK:
            ret = get_lcore_mask(out, outlen);
            break;
        case SOCKOPT_NETIF_GET_LCORE_BASIC:
            if (!in || inlen != sizeof(lcoreid_t))
                return EDPVS_INVAL;
            cid = *(lcoreid_t *)in;
            if (!is_lcore_id_valid(cid))
                return EDPVS_INVAL;
            ret = get_lcore_basic(cid, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_LCORE_STATS:
            if (!in || inlen != sizeof(lcoreid_t))
                return EDPVS_INVAL;
            cid = *(lcoreid_t *)in;
            if (!is_lcore_id_valid(cid))
                return EDPVS_INVAL;
            ret = get_lcore_stats(cid, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_PORT_LIST:
            ret = get_port_list(out, outlen);
            break;
        case SOCKOPT_NETIF_GET_PORT_BASIC:
            if (!in)
                return EDPVS_INVAL;
            name = (char *)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = get_port_basic(port, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_PORT_STATS:
            if (!in)
                return EDPVS_INVAL;
            name = (char *)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = get_port_stats(port, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_PORT_XSTATS:
            if (!in)
                return EDPVS_INVAL;
            name = (char *)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = get_port_xstats(port, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_PORT_EXT_INFO:
            if (!in)
                return EDPVS_INVAL;
            name = (char *)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = get_port_ext_info(port, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_BOND_STATUS:
            if (!in)
                return EDPVS_INVAL;
            name = (char*)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = get_bond_status(port, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_MADDR:
            if (!in)
                return EDPVS_INVAL;
            name = (char *)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = netif_get_multicast_addrs(port, out, outlen);
            break;
        default:
            RTE_LOG(WARNING, NETIF,
                    "[%s] invalid netif get cmd: %d\n", __func__, opt);
            ret = EDPVS_NOTSUPP;
            break;
    }

    if (EDPVS_OK != ret)
        RTE_LOG(ERR, NETIF, "[%s] %s for netif sockmsg opt %d)\n",
                __func__, dpvs_strerror(ret), opt);

    return ret;
}

static int set_lcore(const netif_lcore_set_t *lcore_cfg)
{
    assert(lcore_cfg);

    return EDPVS_OK;
}

static int set_port(struct netif_port *port, const netif_nic_set_t *port_cfg)
{
    struct rte_ether_addr ea;
    assert(port_cfg);

    if (port_cfg->promisc_on) {
        if (rte_eth_promiscuous_get(port->id) != 1)
            rte_eth_promiscuous_enable(port->id);
        RTE_LOG(INFO, NETIF, "[%s] promiscuous mode for %s enabled\n", __func__, port_cfg->pname);
    } else if (port_cfg->promisc_off) {
        if (rte_eth_promiscuous_get(port->id) != 0)
            rte_eth_promiscuous_disable(port->id);
        RTE_LOG(INFO, NETIF, "[%s] promiscuous mode for %s disabled\n", __func__, port_cfg->pname);
    }

    if (port_cfg->allmulticast_on) {
        if (rte_eth_allmulticast_get(port->id) != 1)
            rte_eth_allmulticast_enable(port->id);
        RTE_LOG(INFO, NETIF, "[%s] allmulticast for %s enabled\n", __func__, port_cfg->pname);
    } else if (port_cfg->allmulticast_off) {
        if (rte_eth_allmulticast_get(port->id) != 0) {
            rte_eth_allmulticast_disable(port->id);
            netif_set_mc_list(port);
        }
        RTE_LOG(INFO, NETIF, "[%s] allmulticast for %s disabled\n", __func__, port_cfg->pname);
    }

    if (port_cfg->forward2kni_on) {
        port->flag |= NETIF_PORT_FLAG_FORWARD2KNI;
        RTE_LOG(INFO, NETIF, "[%s] forward2kni mode for %s enabled\n",
            __func__, port_cfg->pname);
    } else if (port_cfg->forward2kni_off) {
        port->flag &= ~(NETIF_PORT_FLAG_FORWARD2KNI);
        RTE_LOG(INFO, NETIF, "[%s] forward2kni mode for %s disabled\n",
            __func__, port_cfg->pname);
    }

    if (port_cfg->link_status_up) {
        int err;
        struct rte_eth_link link;
        err = rte_eth_dev_set_link_up(port->id);
        rte_eth_link_get(port->id, &link);
        if (link.link_status == ETH_LINK_DOWN) {
            RTE_LOG(WARNING, NETIF, "set %s link up [ FAIL ] -- %d\n",
                    port_cfg->pname, err);
        } else {
            RTE_LOG(INFO, NETIF, "set %s link up [ OK ]"
                    " --- speed %dMbps %s-duplex %s-neg\n",
                    port_cfg->pname, link.link_speed,
                    link.link_duplex ? "full" : "half",
                    link.link_autoneg ? "auto" : "fixed");
        }
    } else if (port_cfg->link_status_down) {
        int err;
        struct rte_eth_link link;
        err = rte_eth_dev_set_link_down(port->id);
        rte_eth_link_get(port->id, &link);
        if (link.link_status == ETH_LINK_UP) {
            RTE_LOG(WARNING, NETIF, "set %s link down [ FAIL ] -- %d\n",
                    port_cfg->pname, err);
        } else {
            RTE_LOG(INFO, NETIF, "set %s link down [ OK ]\n", port_cfg->pname);
        }
    }

    memset(&ea, 0, sizeof(ea));
    sscanf(port_cfg->macaddr, "%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned *)&ea.addr_bytes[0],
            (unsigned *)&ea.addr_bytes[1],
            (unsigned *)&ea.addr_bytes[2],
            (unsigned *)&ea.addr_bytes[3],
            (unsigned *)&ea.addr_bytes[4],
            (unsigned *)&ea.addr_bytes[5]);
    if (rte_is_valid_assigned_ether_addr(&ea)) {
        if (port->type == PORT_TYPE_BOND_MASTER) {
            if (rte_eth_bond_mac_address_set(port->id, &ea) < 0) {
                RTE_LOG(WARNING, NETIF, "fail to set %s's macaddr to be %s\n",
                        port->name, port_cfg->macaddr);
            } else {
                RTE_LOG(INFO, NETIF, "set %s's macaddr to be %s\n",
                        port->name, port_cfg->macaddr);
                port->addr = ea;
            }
        } else {
            if (!rte_eth_dev_mac_addr_add(port->id, &ea, 0) &&
                    !rte_eth_dev_default_mac_addr_set(port->id, &ea)) {
                RTE_LOG(INFO, NETIF, "set %s's macaddr to be %s\n",
                        port->name, port_cfg->macaddr);
                port->addr = ea;
            } else {
                RTE_LOG(WARNING, NETIF, "fail to set %s's macaddr to be %s\n",
                        port->name, port_cfg->macaddr);
            }
        }
    }

    if (port_cfg->tc_egress_on)
        port->flag |= NETIF_PORT_FLAG_TC_EGRESS;
    else if (port_cfg->tc_egress_off)
        port->flag &= (~NETIF_PORT_FLAG_TC_EGRESS);

    if (port_cfg->tc_ingress_on)
        port->flag |= NETIF_PORT_FLAG_TC_INGRESS;
    else if (port_cfg->tc_ingress_off)
        port->flag &= (~NETIF_PORT_FLAG_TC_INGRESS);

    if (port_cfg->lldp_on)
        port->flag |= NETIF_PORT_FLAG_LLDP;
    else if (port_cfg->lldp_off)
        port->flag &= (~NETIF_PORT_FLAG_LLDP);

    return EDPVS_OK;
}

static int set_bond(struct netif_port *port, const netif_bond_set_t *bond_cfg)
{
    int i, j;
    assert(bond_cfg);
    switch (bond_cfg->opt) {
    case OPT_MODE:
    {
        if (!rte_eth_bond_mode_set(port->id, bond_cfg->param.mode)) {
            RTE_LOG(INFO, NETIF, "%s's mode changed: %d -> %d\n",
                    port->name, port->bond->master.mode, bond_cfg->param.mode);
            port->bond->master.mode = bond_cfg->param.mode;
        }
        break;
    }
    case OPT_SLAVE:
    {
        struct netif_port *slave;
        slave = netif_port_get_by_name(bond_cfg->param.slave);
        if (!slave)
            return EDPVS_NOTEXIST;
        if (bond_cfg->act == ACT_ADD) {
            if (!rte_eth_bond_slave_add(port->id, slave->id)) {
                RTE_LOG(INFO, NETIF, "slave %s is added to %s\n",
                        slave->name, port->name);
                port->bond->master.slaves[port->bond->master.slave_nb++] = slave;
            }
        } else if (bond_cfg->act == ACT_DEL) {
            if (!rte_eth_bond_slave_remove(port->id, slave->id)) {
                RTE_LOG(INFO, NETIF, "slave %s is removed from %s\n",
                        slave->name, port->name);
                for (i = 0, j = 0; i < port->bond->master.slave_nb; i++) {
                    if (port->bond->master.slaves[i]->id == slave->id)
                        continue;
                    port->bond->master.slaves[j++] = port->bond->master.slaves[i];
                }
                port->bond->master.slave_nb--;
            }
        }
        if (port->netif_ops->op_update_addr) {
            if (port->netif_ops->op_update_addr(port) != EDPVS_OK)
                RTE_LOG(ERR, NETIF, "%s: fail to update %s's mac address!\n", __func__, port->name);
        }
        break;
    }
    case OPT_PRIMARY:
    {
        struct netif_port *primary;
        primary = netif_port_get_by_name(bond_cfg->param.primary);
        if (!primary)
            return EDPVS_NOTEXIST;
        if (!rte_eth_bond_primary_set(port->id, primary->id)) {
            RTE_LOG(INFO, NETIF, "%s's primary slave changed: %s -> %s\n",
                    port->name, port->bond->master.primary->name, primary->name);
            port->bond->master.primary = primary;
        }
        if (port->netif_ops->op_update_addr) {
            if (port->netif_ops->op_update_addr(port) != EDPVS_OK)
                RTE_LOG(ERR, NETIF, "%s: fail to update %s's mac address!\n", __func__, port->name);
        }
        break;
    }
    case OPT_XMIT_POLICY:
    {
        int xp = -1;
        if (!strcmp(bond_cfg->param.xmit_policy, "LAYER2") ||
                !strcmp(bond_cfg->param.xmit_policy, "layer2"))
            xp = BALANCE_XMIT_POLICY_LAYER2;
        else if (!strcmp(bond_cfg->param.xmit_policy, "LAYER23") ||
                !strcmp(bond_cfg->param.xmit_policy, "layer23"))
            xp = BALANCE_XMIT_POLICY_LAYER23;
        else if (!strcmp(bond_cfg->param.xmit_policy, "LAYER34") ||
                !strcmp(bond_cfg->param.xmit_policy, "layer34"))
            xp = BALANCE_XMIT_POLICY_LAYER34;

        if (xp >=0 && !rte_eth_bond_xmit_policy_set(port->id, xp)) {
            RTE_LOG(INFO, NETIF, "set %s's xmit-policy to be %s\n",
                    port->name, bond_cfg->param.xmit_policy);
        }
        break;
    }
    case OPT_LINK_MONITOR_INTERVAL:
    {
        if (!rte_eth_bond_link_monitoring_set(port->id,
                    bond_cfg->param.link_monitor_interval)) {
            RTE_LOG(INFO, NETIF, "set %s's link-monitor-interval to be %d ms\n",
                    port->name, bond_cfg->param.link_monitor_interval);
        }
        break;
    }
    case OPT_LINK_DOWN_PROP:
    {
        if (!rte_eth_bond_link_down_prop_delay_set(port->id,
                    bond_cfg->param.link_down_prop)) {
            RTE_LOG(INFO, NETIF, "set %s's link-down-prop to be %d ms\n",
                    port->name, bond_cfg->param.link_down_prop);
        }
        break;
    }
    case OPT_LINK_UP_PROP:
    {
        if (!rte_eth_bond_link_up_prop_delay_set(port->id,
                    bond_cfg->param.link_up_prop)) {
            RTE_LOG(INFO, NETIF, "set %s's link-up-prop to be %d ms\n",
                    port->name, bond_cfg->param.link_up_prop);
        }
        break;
    }
    default:
        return EDPVS_NOTSUPP;
    }
    return EDPVS_OK;
}

static int netif_sockopt_set(sockoptid_t opt, const void *in, size_t inlen)
{
    int ret;
    switch (opt) {
        case SOCKOPT_NETIF_SET_LCORE:
        {
            if (!in || inlen != sizeof(netif_lcore_set_t))
                return EDPVS_INVAL;
            if (!is_lcore_id_valid(((netif_lcore_set_t *)in)->cid))
                return EDPVS_INVAL;
            ret = set_lcore(in);
            break;
        }
        case SOCKOPT_NETIF_SET_PORT:
        {
            struct netif_port *port;
            if (!in || inlen != sizeof(netif_nic_set_t))
                return EDPVS_INVAL;
            port = netif_port_get_by_name(((netif_nic_set_t *)in)->pname);
            if (!port)
                return EDPVS_INVAL;
            ret = set_port(port, in);
            break;
        }
        case SOCKOPT_NETIF_SET_BOND:
        {
            struct netif_port *port;
            if (!in || inlen != sizeof(netif_bond_set_t))
                return EDPVS_INVAL;
            port = netif_port_get_by_name(((netif_bond_set_t *)in)->name);
            if (!port || port->type != PORT_TYPE_BOND_MASTER)
                return EDPVS_INVAL;
            ret = set_bond(port, in);
            break;
        }
        default:
            RTE_LOG(WARNING, NETIF, "[%s] invalid netif set cmd: %d\n", __func__, opt);
            return EDPVS_INVAL;
    }

    if (EDPVS_OK != ret)
        RTE_LOG(ERR, NETIF, "[%s] %s\n", __func__, dpvs_strerror(ret));

    return EDPVS_OK;
}

struct dpvs_sockopts netif_sockopt = {
    .version = SOCKOPT_VERSION,
    .get_opt_min = SOCKOPT_NETIF_GET_LCORE_MASK,
    .get_opt_max = SOCKOPT_NETIF_GET_MAX,
    .get = netif_sockopt_get,
    .set_opt_min = SOCKOPT_NETIF_SET_LCORE,
    .set_opt_max = SOCKOPT_NETIF_SET_MAX,
    .set = netif_sockopt_set,
};

int netif_ctrl_init(void)
{
    int err;

    if ((err = lcore_stats_msg_init()) != EDPVS_OK)
        return err;

    if ((err = sockopt_register(&netif_sockopt)) != EDPVS_OK)
        return err;

    if ((err = kni_ctrl_init()) != EDPVS_OK)
        return err;

    return EDPVS_OK;
}

int netif_ctrl_term(void)
{
    int err;

    if ((err = kni_ctrl_term()) != EDPVS_OK)
        return err;

    if ((err = sockopt_unregister(&netif_sockopt)) != EDPVS_OK)
        return err;

    if ((err = lcore_stats_msg_term()) != EDPVS_OK)
        return err;

    return EDPVS_OK;
}
