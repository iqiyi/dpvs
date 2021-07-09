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

#
# enable as needed.
#
# TODO: use standard way to define compile flags.
#

CONFIG_IXGEB_PMD=y
CONFIG_PDUMP=y

CFLAGS += -D DPVS_MAX_SOCKET=2
CFLAGS += -D DPVS_MAX_LCORE=64

#CFLAGS += -D CONFIG_DPVS_NEIGH_DEBUG
#CFLAGS += -D CONFIG_RECORD_BIG_LOOP
#CFLAGS += -D CONFIG_DPVS_SAPOOL_DEBUG
#CFLAGS += -D CONFIG_DPVS_IPVS_DEBUG
#CFLAGS += -D CONFIG_SYNPROXY_DEBUG
#CFLAGS += -D CONFIG_TIMER_MEASURE
#CFLAGS += -D CONFIG_TIMER_DEBUG
#CFLAGS += -D DPVS_CFG_PARSER_DEBUG
#CFLAGS += -D NETIF_BONDING_DEBUG
#CFLAGS += -D CONFIG_TC_DEBUG
#CFLAGS += -D CONFIG_DPVS_IPVS_STATS_DEBUG
#CFLAGS += -D CONFIG_DPVS_IP_HEADER_DEBUG
#CFLAGS += -D CONFIG_DPVS_MBUF_DEBUG
#CFLAGS += -D CONFIG_DPVS_IPSET_DEBUG
#CFLAGS += -D CONFIG_NDISC_DEBUG
#CFLAGS += -D CONFIG_MSG_DEBUG
#CFLAGS += -D CONFIG_DPVS_MP_DEBUG
#CFLAGS += -D CONFIG_ICMP_REDIRECT_CORE

# for ixgbe nic
ifeq ($(CONFIG_IXGEB_PMD), y)
CFLAGS += -D CONFIG_DPVS_FDIR
endif

ifeq ($(CONFIG_PDUMP), y)
CFLAGS += -D CONFIG_DPVS_PDUMP
endif

GCC_MAJOR = $(shell echo __GNUC__ | $(CC) -E -x c - | tail -n 1)
GCC_MINOR = $(shell echo __GNUC_MINOR__ | $(CC) -E -x c - | tail -n 1)
GCC_VERSION = $(GCC_MAJOR)$(GCC_MINOR)

