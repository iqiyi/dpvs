#
# DPVS is a software load balancer (Virtual Server) based on DPDK.
#
# Copyright (C) 2021 iQIYI (www.iqiyi.com).
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

CFLAGS += -D DPVS_MAX_SOCKET=$(CONFIG_DPVS_MAX_SOCKET)
CFLAGS += -D DPVS_MAX_LCORE=$(CONFIG_DPVS_MAX_LCORE)

ifeq ($(CONFIG_DPVS_AGENT), y)
CFLAGS += -D CONFIG_DPVS_AGENT
endif

# for ixgbe nic
ifeq ($(CONFIG_IXGEB_PMD), y)
CFLAGS += -D CONFIG_DPVS_FDIR
endif

ifeq ($(CONFIG_DPVS_LOG), y)
CFLAGS += -D CONFIG_DPVS_LOG
endif

ifeq ($(CONFIG_PDUMP), y)
CFLAGS += -D CONFIG_DPVS_PDUMP
endif

ifeq ($(CONFIG_ICMP_REDIRECT_CORE), y)
CFLAGS += -D CONFIG_ICMP_REDIRECT_CORE
endif

ifeq ($(CONFIG_DPVS_NEIGH_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_NEIGH_DEBUG
endif

ifeq ($(CONFIG_RECORD_BIG_LOOP), y)
CFLAGS += -D CONFIG_RECORD_BIG_LOOP
endif

ifeq ($(CONFIG_DPVS_SAPOOL_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_SAPOOL_DEBUG
endif

ifeq ($(CONFIG_DPVS_IPVS_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_IPVS_DEBUG
endif

ifeq ($(CONFIG_DPVS_SERVICE_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_SERVICE_DEBUG
endif

ifeq ($(CONFIG_SYNPROXY_DEBUG), y)
CFLAGS += -D CONFIG_SYNPROXY_DEBUG
endif

ifeq ($(CONFIG_TIMER_MEASURE), y)
CFLAGS += -D CONFIG_TIMER_MEASURE
endif

ifeq ($(CONFIG_TIMER_DEBUG), y)
CFLAGS += -D CONFIG_TIMER_DEBUG
endif

ifeq ($(CONFIG_DPVS_CFG_PARSER_DEBUG), y)
CFLAGS += -D DPVS_CFG_PARSER_DEBUG
endif

ifeq ($(CONFIG_NETIF_BONDING_DEBUG), y)
CFLAGS += -D NETIF_BONDING_DEBUG
endif

ifeq ($(CONFIG_TC_DEBUG), y)
CFLAGS += -D CONFIG_TC_DEBUG
endif

ifeq ($(CONFIG_DPVS_IPVS_STATS_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_IPVS_STATS_DEBUG
endif

ifeq ($(CONFIG_DPVS_IP_HEADER_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_IP_HEADER_DEBUG
endif

ifeq ($(CONFIG_DPVS_MBUF_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_MBUF_DEBUG
endif

ifeq ($(CONFIG_DPVS_IPSET_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_IPSET_DEBUG
endif

ifeq ($(CONFIG_NDISC_DEBUG), y)
CFLAGS += -D CONFIG_NDISC_DEBUG
endif

ifeq ($(CONFIG_MSG_DEBUG), y)
CFLAGS += -D CONFIG_MSG_DEBUG
endif

ifeq ($(CONFIG_DPVS_MP_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_MP_DEBUG
endif

ifeq ($(CONFIG_DPVS_NETIF_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_NETIF_DEBUG
endif

ifeq ($(CONFIG_DPVS_ICMP_DEBUG), y)
CFLAGS += -D CONFIG_DPVS_ICMP_DEBUG
endif

GCC_MAJOR = $(shell echo __GNUC__ | $(CC) -E -x c - | tail -n 1)
GCC_MINOR = $(shell echo __GNUC_MINOR__ | $(CC) -E -x c - | tail -n 1)
GCC_VERSION = $(GCC_MAJOR)$(GCC_MINOR)

