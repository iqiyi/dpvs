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

ifeq ($(RTE_SDK),)
$(error "The variable RTE_SDK is not defined.")
endif
# default target, may be overriden.
RTE_TARGET ?= build

DPDKDIR := $(RTE_SDK)/$(RTE_TARGET)

INCDIRS += -I $(DPDKDIR)/include

CFLAGS += -include $(DPDKDIR)/include/rte_config.h

LIBS += -L $(DPDKDIR)/lib

LIBS += -Wl,--no-as-needed -fvisibility=default \
        -Wl,--whole-archive -lrte_pmd_vmxnet3_uio -lrte_pmd_i40e -lrte_pmd_ixgbe -lrte_pmd_ena \
		-lrte_pmd_e1000 -lrte_pmd_bnxt -lrte_pmd_ring -lrte_pmd_bond -lrte_ethdev -lrte_ip_frag \
		-Wl,--whole-archive -lrte_hash -lrte_kvargs -Wl,-lrte_mbuf -lrte_eal \
		-Wl,-lrte_mempool -lrte_ring -lrte_cmdline -lrte_cfgfile -lrte_kni \
		-lrte_mempool_ring -lrte_timer -lrte_net -Wl,-lrte_pmd_virtio \
		-lrte_pci -lrte_bus_pci -lrte_bus_vdev -lrte_lpm -lrte_pdump \
		-Wl,--no-whole-archive -lrt -lm -ldl -lcrypto

ifeq ($(CONFIG_PDUMP), y)
LIBS += -Wl,--whole-archive -lrte_acl -lrte_member -lrte_eventdev -lrte_reorder -lrte_cryptodev \
		-lrte_vhost -lrte_pmd_pcap

ifneq ("$(wildcard $(RTE_SDK)/$(RTE_TARGET)/lib/librte_bus_vmbus.a)", "")
	LIBS += -lrte_bus_vmbus
endif

ifneq ("$(wildcard $(RTE_SDK)/$(RTE_TARGET)/lib/librte_pmd_netvsc.a)", "")
	LIBS += -lrte_pmd_netvsc
endif

LIBS += -Wl,--no-whole-archive -lpcap
endif

ifeq ($(CONFIG_MLX5), y)
LIBS += -Wl,--whole-archive -lrte_pmd_mlx5 -Wl,--no-whole-archive
LIBS += -libverbs -lmlx5 -lmnl
endif

