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
#ifndef __DPVS_DPDK_H__
#define __DPVS_DPDK_H__
#include <rte_common.h>
#include <rte_version.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_string_fns.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>
#include <rte_timer.h>
#include <rte_jhash.h>
#include <rte_ip_frag.h>
#include <rte_eth_bond.h>
#include <rte_eth_bond_8023ad.h>
#include <rte_ethdev_driver.h>
#include "mbuf.h"
#ifndef CONFIG_KNI_VIRTIO_USER
#include <rte_kni.h>
#endif
#ifdef CONFIG_DPVS_PDUMP
#include <rte_pdump.h>
#endif

#ifdef CONFIG_DPVS_LOG
#ifdef RTE_LOG
extern int dpvs_log(uint32_t level, uint32_t logtype, const char *func, int line,
        const char *format, ...) __rte_format_printf(5, 6);
#undef RTE_LOG
#define RTE_LOG(l, t, ...)                  \
    dpvs_log(RTE_LOG_ ## l,                   \
        RTE_LOGTYPE_ ## t,  __func__, __LINE__, # t ": " __VA_ARGS__)
#endif
#endif

#if RTE_VERSION < RTE_VERSION_NUM(21, 0, 0, 0)
#define RTE_ETHER_ADDR_PRT_FMT     "%02X:%02X:%02X:%02X:%02X:%02X"
#define RTE_ETHER_ADDR_BYTES(mac_addrs) ((mac_addrs)->addr_bytes[0]), \
                     ((mac_addrs)->addr_bytes[1]), \
                     ((mac_addrs)->addr_bytes[2]), \
                     ((mac_addrs)->addr_bytes[3]), \
                     ((mac_addrs)->addr_bytes[4]), \
                     ((mac_addrs)->addr_bytes[5])

#define RTE_ETHER_ADDR_FMT_SIZE         18
#endif

#endif /* __DPVS_DPDK_H__ */
