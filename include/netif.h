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
#ifndef __DPVS_NETIF_H__
#define __DPVS_NETIF_H__
#include "list.h"
#include "dpdk.h"
#include "inetaddr.h"
#include "timer.h"
#include "tc/tc.h"

#define RTE_LOGTYPE_NETIF RTE_LOGTYPE_USER1

enum {
    NETIF_PORT_FLAG_ENABLED                 = (0x1<<0),
    NETIF_PORT_FLAG_RUNNING                 = (0x1<<1),
    NETIF_PORT_FLAG_STOPPED                 = (0x1<<2),
    NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD      = (0x1<<3),
    NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD      = (0x1<<4),
    NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD     = (0x1<<5),
    NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD     = (0x1<<6),
    NETIF_PORT_FLAG_TX_VLAN_INSERT_OFFLOAD  = (0x1<<7),
    NETIF_PORT_FLAG_RX_VLAN_STRIP_OFFLOAD   = (0x1<<8),
    NETIF_PORT_FLAG_FORWARD2KNI             = (0x1<<9),
    NETIF_PORT_FLAG_TC_EGRESS               = (0x1<<10),
    NETIF_PORT_FLAG_TC_INGRESS              = (0x1<<11),
    NETIF_PORT_FLAG_NO_ARP                  = (0x1<<12),
};

/* max tx/rx queue number for each nic */
#define NETIF_MAX_QUEUES            16
/* max nic number used in the program */
#define NETIF_MAX_PORTS             4096
/* maximum pkt number at a single burst */
#define NETIF_MAX_PKT_BURST         32
/* maximum bonding slave number */
#define NETIF_MAX_BOND_SLAVES       32
/* maximum number of hw addr */
#define NETIF_MAX_HWADDR            64
/* maximum number of kni device */
#define NETIF_MAX_KNI               64
/* maximum number of DPDK rte device */
#define NETIF_MAX_RTE_PORTS         64

#define NETIF_ALIGN                 32

#define NETIF_PORT_ID_INVALID       0xFF
#define NETIF_PORT_ID_ALL           NETIF_PORT_ID_INVALID

#define NETIF_LCORE_ID_INVALID      0xFF

/************************* lcore conf  ***************************/
struct rx_partner;

/* RX/TX queue conf for lcore */
struct netif_queue_conf
{
    queueid_t id; 
    uint16_t len;
    uint16_t kni_len;
    struct rx_partner *isol_rxq;
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    struct rte_mbuf *kni_mbufs[NETIF_MAX_PKT_BURST];
} __rte_cache_aligned;

/*
 * RX/TX port conf for lcore.
 * Multiple queues of a port may be processed by a lcore.
 */
struct netif_port_conf
{
    portid_t id; 
    /* rx/tx queues for this lcore to process*/
    int nrxq;
    int ntxq;
    /* rx/tx queue list for this lcore to process */
    struct netif_queue_conf rxqs[NETIF_MAX_QUEUES];
    struct netif_queue_conf txqs[NETIF_MAX_QUEUES];
} __rte_cache_aligned;

/*
 *  lcore conf
 *  Multiple ports may be processed by a lcore.
 */
struct netif_lcore_conf
{
    lcoreid_t id; 
    /* nic number of this lcore to process */
    int nports;
    /* port list of this lcore to process */
    struct netif_port_conf pqs[NETIF_MAX_RTE_PORTS];
} __rte_cache_aligned;

/* isolate RX lcore */
struct rx_partner {
    lcoreid_t cid;
    portid_t pid;
    queueid_t qid;
    struct rte_ring *rb;
    struct netif_queue_conf *rxq; /* reverse rxq pointer */
    struct list_head lnode;
};

/**************************** lcore statistics ***************************/
struct netif_lcore_stats
{
    uint64_t lcore_loop; /* Total number of loops since start */
    uint64_t pktburst;  /* Total number of receive bursts */
    uint64_t zpktburst; /* Total number of receive bursts with ZERO packets */
    uint64_t fpktburst; /* Total number of receive bursts with MAX packets */
    uint64_t z2hpktburst; /* Total number of receive bursts with [0, 0.5*MAX] packets */
    uint64_t h2fpktburst; /* Total number of receive bursts with (0.5*MAX, MAX] packets */
    uint64_t ipackets; /* Total number of successfully received packets. */
    uint64_t ibytes; /* Total number of successfully received bytes. */
    uint64_t opackets; /* Total number of successfully transmitted packets. */
    uint64_t obytes;/* Total number of successfully transmitted bytes. */
    uint64_t dropped; /* Total number of dropped packets by software. */
} __rte_cache_aligned;

/**************************** lcore loop job ****************************/
enum netif_lcore_job_type {
    NETIF_LCORE_JOB_INIT      = 0,
    NETIF_LCORE_JOB_LOOP      = 1,
    NETIF_LCORE_JOB_SLOW      = 2,
    NETIF_LCORE_JOB_TYPE_MAX  = 3,
};

struct netif_lcore_loop_job
{
    char name[32];
    void (*func)(void *arg);
    void *data;
    enum netif_lcore_job_type type;
    uint32_t skip_loops; /* for NETIF_LCORE_JOB_SLOW type only */
#ifdef CONFIG_RECORD_BIG_LOOP
    uint32_t job_time[DPVS_MAX_LCORE];
#endif
    struct list_head list;
} __rte_cache_aligned;

/******************* packet type for upper protocol *********************/
struct pkt_type {
    uint16_t type; /* htons(ether-type) */
    struct netif_port *port; /* NULL for wildcard */
    int (*func)(struct rte_mbuf *mbuf, struct netif_port *port);
    struct list_head list;
} __rte_cache_aligned;

typedef enum {
    ETH_PKT_HOST,
    ETH_PKT_BROADCAST,
    ETH_PKT_MULTICAST,
    ETH_PKT_OTHERHOST,
} eth_type_t;

/************************ data type for NIC ****************************/
#define DEVICE_NAME_MAX_LEN 32
typedef enum {
    PORT_TYPE_GENERAL,
    PORT_TYPE_BOND_MASTER,
    PORT_TYPE_BOND_SLAVE,
    PORT_TYPE_VLAN,
    PORT_TYPE_TUNNEL,
    PORT_TYPE_INVAL,
} port_type_t;

struct netif_kni {
    char name[DEVICE_NAME_MAX_LEN];
    struct rte_kni *kni;
    struct ether_addr addr;
    struct dpvs_timer kni_rtnl_timer;
    int kni_rtnl_fd;
} __rte_cache_aligned;

union netif_bond {
    struct {
        int mode; /* bonding mode */
        int slave_nb; /* slave number */
        struct netif_port *primary; /* primary device */
        struct netif_port *slaves[NETIF_MAX_BOND_SLAVES]; /* slave devices */
    } master;
    struct {
        struct netif_port *master;
    } slave;
} __rte_cache_aligned;

struct netif_ops {
    int (*op_init)(struct netif_port *dev);
    int (*op_uninit)(struct netif_port *dev);
    int (*op_open)(struct netif_port *dev);
    int (*op_stop)(struct netif_port *dev);
    int (*op_xmit)(struct rte_mbuf *m, struct netif_port *dev);
    int (*op_set_mc_list)(struct netif_port *dev);
    int (*op_filter_supported)(struct netif_port *dev, enum rte_filter_type fltype);
    int (*op_set_fdir_filt)(struct netif_port *dev, enum rte_filter_op op,
                            const struct rte_eth_fdir_filter *filt);
    int (*op_get_queue)(struct netif_port *dev, lcoreid_t cid, queueid_t *qid);
    int (*op_get_link)(struct netif_port *dev, struct rte_eth_link *link);
    int (*op_get_promisc)(struct netif_port *dev, bool *promisc);
    int (*op_get_stats)(struct netif_port *dev, struct rte_eth_stats *stats);
};

struct netif_hw_addr {
    struct list_head        list;
    struct ether_addr       addr;
    rte_atomic32_t          refcnt;
    /*
     * - sync only once!
     *
     *   for HA in upper dev, no matter how many times it's added,
     *   only sync once to lower (when sync_cnt is zero).
     *
     *   and HA (upper)'s refcnt++, to mark lower dev own's it.
     *
     * - when to unsync?
     *
     *   when del if HA (upper dev)'s refcnt is 1 and syn_cnt is not zero.
     *   means lower dev is the only owner and need be unsync.
     */
    int                     sync_cnt;
};

struct netif_hw_addr_list {
    struct list_head        addrs;
    int                     count;
};

struct netif_port {
    char                    name[DEVICE_NAME_MAX_LEN];  /* device name */
    portid_t                id;                         /* device id */
    port_type_t             type;                       /* device type */
    uint16_t                flag;                       /* device flag */
    int                     nrxq;                       /* rx queue number */
    int                     ntxq;                       /* tx queue numbe */
    uint16_t                rxq_desc_nb;                /* rx queue descriptor number */
    uint16_t                txq_desc_nb;                /* tx queue descriptor number */
    struct ether_addr       addr;                       /* MAC address */
    struct netif_hw_addr_list mc;                       /* HW multicast list */
    int                     socket;                     /* socket id */
    int                     hw_header_len;              /* HW header length */
    uint16_t                mtu;                        /* device mtu */
    struct rte_mempool      *mbuf_pool;                 /* packet mempool */
    struct rte_eth_dev_info dev_info;                   /* PCI Info + driver name */
    struct rte_eth_conf     dev_conf;                   /* device configuration */
    struct rte_eth_stats    stats;                      /* last device statistics */
    rte_rwlock_t            dev_lock;                   /* device lock */
    struct list_head        list;                       /* device list node hashed by id */
    struct list_head        nlist;                      /* device list node hashed by name */
    struct inet_device      *in_ptr;
    struct inet_device      *in6_ptr;
    struct netif_kni        kni;                        /* kni device */
    union netif_bond        *bond;                      /* bonding conf */
    struct vlan_info        *vlan_info;                 /* VLANs info for real device */
    struct netif_tc         tc;                         /* traffic control */
    struct netif_ops        *netif_ops;
} __rte_cache_aligned;

/**************************** lcore API *******************************/
int netif_xmit(struct rte_mbuf *mbuf, struct netif_port *dev);
int netif_hard_xmit(struct rte_mbuf *mbuf, struct netif_port *dev);
int netif_rcv(struct netif_port *dev, __be16 eth_type, struct rte_mbuf *mbuf);
int netif_print_lcore_conf(char *buf, int *len, bool is_all, portid_t pid);
int netif_print_lcore_queue_conf(lcoreid_t cid, char *buf, int *len, bool title);
void netif_get_slave_lcores(uint8_t *nb, uint64_t *mask);
void netif_update_master_loop_cnt(void);
// function only for init or termination //
int netif_register_master_xmit_msg(void);
int netif_lcore_conf_set(int lcores, const struct netif_lcore_conf *lconf);
int netif_lcore_loop_job_register(struct netif_lcore_loop_job *lcore_job);
int netif_lcore_loop_job_unregister(struct netif_lcore_loop_job *lcore_job);
int netif_lcore_start(void);
bool is_lcore_id_valid(lcoreid_t cid);

/************************** protocol API *****************************/
int netif_register_pkt(struct pkt_type *pt);
int netif_unregister_pkt(struct pkt_type *pt);

/**************************** port API ******************************/
int netif_fdir_filter_set(struct netif_port *port, enum rte_filter_op opcode, 
                          const struct rte_eth_fdir_filter *fdir_flt);
struct netif_port* netif_port_get(portid_t id);
/* port_conf can be NULL for default port configure */
int netif_print_port_conf(const struct rte_eth_conf *port_conf, char *buf, int *len);
int netif_print_port_queue_conf(portid_t pid, char *buf, int *len);
/* get netif by name, fail return NULL */
struct netif_port* netif_port_get_by_name(const char *name);
// function only for init or termination //
int netif_port_conf_get(struct netif_port *port, struct rte_eth_conf *eth_conf);
int netif_port_conf_set(struct netif_port *port, const struct rte_eth_conf *conf);
int netif_port_start(struct netif_port *port); // start nic and wait until up
int netif_port_stop(struct netif_port *port); // stop nic
int netif_set_mc_list(struct netif_port *port);
int __netif_set_mc_list(struct netif_port *port);
int netif_get_queue(struct netif_port *port, lcoreid_t id, queueid_t *qid);
int netif_get_link(struct netif_port *dev, struct rte_eth_link *link);
int netif_get_promisc(struct netif_port *dev, bool *promisc);
int netif_get_stats(struct netif_port *dev, struct rte_eth_stats *stats);

/************************** module API *****************************/
int netif_virtual_devices_add(void);
int netif_init(const struct rte_eth_conf *conf);
int netif_term(void); /* netif layer cleanup */
int netif_ctrl_init(void); /* netif ctrl plane init */
int netif_ctrl_term(void); /* netif ctrl plane cleanup */

void netif_cfgfile_init(void);
void netif_keyword_value_init(void);
void install_netif_keywords(void);

/*************************** kni api *******************************/
void kni_process_on_master(void);

static inline void *netif_priv(struct netif_port *dev)
{
    return (char *)dev + __ALIGN_KERNEL(sizeof(struct netif_port), NETIF_ALIGN);
}

static inline struct netif_tc *netif_tc(struct netif_port *dev)
{
    return &dev->tc;
}

struct netif_port *netif_alloc(size_t priv_size, const char *namefmt,
                               unsigned int nrxq, unsigned int ntxq,
                               void (*setup)(struct netif_port *));

int netif_free(struct netif_port *dev);
int netif_port_register(struct netif_port *dev);
int netif_port_unregister(struct netif_port *dev);

static inline int eth_addr_equal(const struct ether_addr *addr1,
                                 const struct ether_addr *addr2)
{
    const uint16_t *a = (const uint16_t *)addr1;
    const uint16_t *b = (const uint16_t *)addr2;

    return ((a[0]^b[0]) | (a[1]^b[1]) | (a[2]^b[2])) == 0;
}

static inline char *eth_addr_dump(const struct ether_addr *ea,
                                  char *buf, size_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             ea->addr_bytes[0], ea->addr_bytes[1],
             ea->addr_bytes[2], ea->addr_bytes[3],
             ea->addr_bytes[4], ea->addr_bytes[5]);
    return buf;
}

#endif /* __DPVS_NETIF_H__ */
