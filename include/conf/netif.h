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
#ifndef __NETIF_CONF_H__
#define __NETIF_CONF_H__
#include <linux/if_ether.h>

#define NETIF_MAX_PORTS     64
#define NETIF_MAX_LCORES    64

/*** type from dpdk.h ***
 * All types defined here must be the same as in dpdk.h,
 * error would occur otherwise */

#define DEVICE_NAME_MAX_LEN             32
#define RTE_ETHDEV_QUEUE_STAT_CNTRS     16
#define NETIF_MAX_BOND_SLAVES           32

typedef uint8_t lcoreid_t;
typedef uint8_t portid_t;
typedef uint16_t queueid_t;

#define NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD  0x1<<3
#define NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD  0x1<<4
#define NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD 0x1<<5
#define NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD 0x1<<6
#define NETIF_PORT_FLAG_FORWARD2KNI   0x1<<9

#define ETH_LINK_DOWN           0
#define ETH_LINK_UP             1

#define ETH_LINK_HALF_DUPLEX    0 /**< Half-duplex connection. */
#define ETH_LINK_FULL_DUPLEX    1 /**< Full-duplex connection. */
#define ETH_LINK_DOWN           0 /**< Link is down. */
#define ETH_LINK_UP             1 /**< Link is up. */
#define ETH_LINK_FIXED          0 /**< No autonegotiation. */
#define ETH_LINK_AUTONEG        1 /**< Autonegotiated. */

/*** end of type from dpdk.h ***/

enum {
    /* get */
    SOCKOPT_NETIF_GET_LCORE_MASK = 500,
    SOCKOPT_NETIF_GET_LCORE_BASIC,
    SOCKOPT_NETIF_GET_LCORE_STATS,
    SOCKOPT_NETIF_GET_PORT_NUM,
    SOCKOPT_NETIF_GET_PORT_BASIC,
    SOCKOPT_NETIF_GET_PORT_DEV_INFO,
    SOCKOPT_NETIF_GET_PORT_STATS,
    SOCKOPT_NETIF_GET_PORT_QUEUE,
    SOCKOPT_NETIF_GET_PORT_MBUFPOOL,
    SOCKOPT_NETIF_GET_BOND_STATUS,
    SOCKOPT_NETIF_GET_MC_ADDRS,
    SOCKOPT_NETIF_GET_MAX,
    /* set */
    SOCKOPT_NETIF_SET_LCORE = 500,
    SOCKOPT_NETIF_SET_PORT,
    SOCKOPT_NETIF_SET_BOND,
    SOCKOPT_NETIF_SET_MAX,
};

/* all lcores in use */
typedef struct netif_lcore_mask_get
{
    lcoreid_t master_lcore_id;
    uint8_t slave_lcore_num;
    uint8_t isol_rx_lcore_num;
    uint64_t slave_lcore_mask;
    uint64_t isol_rx_lcore_mask;
} netif_lcore_mask_get_t;

/* basic lcore info specified by lcore_id  */
typedef struct netif_lcore_basic_get
{
    lcoreid_t lcore_id;
    uint8_t socket_id;
    uint32_t queue_data_len;
    char queue_data[0];
} netif_lcore_basic_get_t;

/* statistics info of lcore_id */
typedef struct netif_lcore_stats_get
{
    lcoreid_t lcore_id;
    uint64_t lcore_loop;
    uint64_t pktburst;
    uint64_t zpktburst;
    uint64_t fpktburst;
    uint64_t z2hpktburst;
    uint64_t h2fpktburst;
    uint64_t ipackets;
    uint64_t ibytes;
    uint64_t opackets;
    uint64_t obytes;
    uint64_t dropped; // software packet drop
} netif_lcore_stats_get_t;

/* nic number in use */
typedef struct netif_nic_num_get
{
    uint8_t nic_num;
    uint8_t phy_pid_base;
    uint8_t phy_pid_end;
    uint8_t bond_pid_base;
    uint8_t bond_pid_end;
    char pid_name_map[NETIF_MAX_PORTS][DEVICE_NAME_MAX_LEN];
} netif_nic_num_get_t;

/* basic nic info specified by port_id */
typedef struct netif_nic_basic_get
{
    portid_t port_id;
    char name[32];
    uint16_t flags; /* NETIF_PORT_FLAG_ */
    uint8_t nrxq;
    uint8_t ntxq;
    char addr[32];
    uint8_t socket_id;
    uint16_t mtu;
    uint32_t link_speed; /* ETH_SPEED_NUM_ */
    uint16_t link_duplex:1; /* ETH_LINK_[HALF/FULL]_DUPLEX */
    uint16_t link_autoneg:1; /* ETH_LINK_SPEED_[AUTONEG/FIXED] */
    uint16_t link_status:1; /* ETH_LINK_[DOWN/UP] */
    uint16_t promisc:1; /* promiscuous mode */
} netif_nic_basic_get_t;

/* dev info specified by port_id */
typedef struct netif_nic_dev_get
{
    portid_t port_id;
    char pci_addr[32]; /* pci address */
    char driver_name[32]; /* device driver name */
    uint32_t if_index; /* index to bound host interface, or 0 if none */
    uint32_t min_rx_bufsize; /* minimum size of RX buffer */
    uint32_t max_rx_pktlen; /* maximum configurable length of RX pkt */
    uint16_t max_rx_queues; /* maximum number of RX queues */
    uint16_t max_tx_queues; /* maximum number of TX queues */
    uint32_t max_mac_addrs; /* maximum number of MAC addressses */
    uint32_t max_hash_mac_addrs; /* maximum number of hash MAC addresses for MTA and UTA */
    uint16_t max_vfs; /* maximum unmber of VFs */
    uint16_t max_vmdq_pools;/* maximum number of VMDq pools */
    uint32_t rx_offload_capa; /* device RX offload capabilities */
    uint32_t tx_offload_capa; /* device TX offload capabilities */
    uint32_t reta_size; /* device redirection table size ,the toatal number of entries */
    uint8_t hash_key_size; /* Hash key size in bytes */
    uint64_t flow_type_rss_offloads;
    /* bit mask of RSS offloads, the bit offset also means flow type*/
    uint16_t vmdq_queue_base; /* first queue ID for VMDQ pools */
    uint16_t vmdq_queue_num; /* queue number ofr VMDQ pools */
    uint16_t vmdq_pool_base; /* first ID of VMDQ pools */
    uint16_t rx_desc_lim_nb_max; /* max allowed number of rx descriptors */
    uint16_t rx_desc_lim_nb_min; /* min allowed number of rx descriptors */
    uint16_t rx_desc_lim_nb_align; /* number of rx desciptors should be aligned to */
    uint16_t tx_desc_lim_nb_max; /* max allowed number of tx descriptors */
    uint16_t tx_desc_lim_nb_min; /* min allowed number of tx descriptors */
    uint16_t tx_desc_lim_nb_align; /* number of tx desciptors should be aligned to */
    uint32_t speed_capa; /* supported speed bitmap (ETH_LINK_SPEED_) */
} netif_nic_dev_get_t;

/* nic statistics specified by port_id */
typedef struct netif_nic_stats_get {
    portid_t port_id;
	uint64_t ipackets;  /* Total number of successfully received packets. */
	uint64_t opackets;  /* Total number of successfully transmitted packets.*/
	uint64_t ibytes;    /* Total number of successfully received bytes. */
	uint64_t obytes;    /* Total number of successfully transmitted bytes. */
	uint64_t imissed;
	/* Total of RX packets dropped by the HW,
     * because there are no available mbufs (i.e. RX queues are full). */
	uint64_t ierrors;   /* Total number of erroneous received packets. */
	uint64_t oerrors;   /* Total number of failed transmitted packets. */
	uint64_t rx_nombuf; /* Total number of RX mbuf allocation failures. */
	uint64_t q_ipackets[RTE_ETHDEV_QUEUE_STAT_CNTRS];
	/* Total number of queue RX packets. */
	uint64_t q_opackets[RTE_ETHDEV_QUEUE_STAT_CNTRS];
	/* Total number of queue TX packets. */
	uint64_t q_ibytes[RTE_ETHDEV_QUEUE_STAT_CNTRS];
	/* Total number of successfully received queue bytes. */
	uint64_t q_obytes[RTE_ETHDEV_QUEUE_STAT_CNTRS];
	/* Total number of successfully transmitted queue bytes. */
	uint64_t q_errors[RTE_ETHDEV_QUEUE_STAT_CNTRS];
	/* Total number of queue packets received that are dropped. */
} netif_nic_stats_get_t;

struct bond_slave_node {
    char name[32];
    char macaddr[32];
    int is_active;
    int is_primary;
};

typedef struct netif_bond_status_get {
    int mode;
    int slave_nb;
    int active_nb;
    struct bond_slave_node slaves[NETIF_MAX_BOND_SLAVES];
    char macaddr[32];
    char xmit_policy[32];
    int link_monitor_interval;
    int link_down_prop_delay;
    int link_up_prop_delay;
} netif_bond_status_get_t;

/* configured queues for all enabled ports */
typedef struct netif_nic_conf_queues
{
    uint32_t cf_queue_len;
    char cf_queue[0];
} netif_nic_conf_queues_t;

/* lcore configure struct */
typedef struct netif_lcore_set {
    lcoreid_t cid;
} netif_lcore_set_t;

/* port configure struct */
typedef struct netif_nic_set {
    char pname[32];
    char macaddr[18];
    uint16_t promisc_on:1;
    uint16_t promisc_off:1;
    uint16_t link_status_up:1;
    uint16_t link_status_down:1;
    uint16_t forward2kni_on:1;
    uint16_t forward2kni_off:1;
} netif_nic_set_t;

typedef struct netif_nic_mbufpool {
    uint32_t available;
    uint32_t inuse;
} netif_nic_mbufpool_t;

typedef struct netif_bond_set {
    char name[32];
    union {
        int mode;
        char slave[32];
        char primary[32];
        char xmit_policy[32];
        int link_monitor_interval;
        int link_down_prop;
        int link_up_prop;
    } param;
    enum {
        ACT_ADD = 1,
        ACT_DEL,
        ACT_SET,
    } act;
    enum {
        OPT_MODE = 1,
        OPT_SLAVE,
        OPT_PRIMARY,
        OPT_XMIT_POLICY,
        OPT_LINK_MONITOR_INTERVAL,
        OPT_LINK_DOWN_PROP,
        OPT_LINK_UP_PROP,
    } opt;
} netif_bond_set_t;

struct netif_mc_list_conf {
    int                 naddr;
    uint8_t             addrs[0][ETH_ALEN];
} __attribute__((__packed__));

#endif
