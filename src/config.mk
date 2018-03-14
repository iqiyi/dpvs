#
# DPVS is a software load balancer (Virtual Server) based on DPDK.
#
# Copyright (C) 2017 iQIYI (www.iqiyi.com).
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

CFLAGS += -D DPVS_MAX_SOCKET=2
CFLAGS += -D DPVS_MAX_LCORE=64

#CFLAGS += -D CONFIG_RECORD_BIG_LOOP
#CFLAGS += -D CONFIG_DPVS_SAPOOL_DEBUG
#CFLAGS += -D CONFIG_DPVS_IPVS_DEBUG
#CFLAGS += -D CONFIG_SYNPROXY_DEBUG
#CFLAGS += -D CONFIG_TIMER_MEASURE
#CFLAGS += -D DPVS_CFG_PARSER_DEBUG
#CFLAGS += -D NETIF_BONDING_DEBUG
#CFLAGS += -D CONFIG_TC_DEBUG
