#   BSD LICENSE
#
#   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
#RTE_TARGET ?= x86_64-native-linuxapp-gcc
RTE_TARGET ?= build

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = dpvs

# all source are stored in SRCS-y
SRCS-y := main.c netif.c ipv4.c ipv4_frag.c neigh.c timer.c route.c inet.c common.c \
		  vlan.c mbuf.c inetaddr.c sa_pool.c icmp.c ctrl.c kni.c netif_addr.c \
		  ip_vs_core.c ip_vs_conn.c ip_vs_laddr.c ip_vs_xmit.c ip_vs_proto.c \
		  ip_vs_service.c ip_vs_dest.c  ip_vs_blklst.c ip_vs_proto_udp.c \
		  ip_vs_proto_tcp.c ip_vs_proto_icmp.c ip_vs_stats.c ip_vs_sched.c \
		  ip_vs_rr.c ip_vs_wrr.c ip_vs_wlc.c ip_vs_synproxy.c pidfile.c \
		  parser.c cfgfile.c global_conf.c

CFLAGS += -O3
#CFLAGS += -g -O0
CFLAGS += -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += $(USER_FLAGS)
CFLAGS += -I $(SRCDIR)/../include/

#CFLAGS += -D CONFIG_RECORD_BIG_LOOP
#CFLAGS += -D CONFIG_DPVS_SAPOOL_DEBUG
#CFLAGS += -D CONFIG_DPVS_IPVS_DEBUG
#CFLAGS += -D CONFIG_SYNPROXY_DEBUG
#CFLAGS += -D CONFIG_MSG_DEBUG
#CFLAGS += -D CONFIG_TIMER_MEASURE
#CFLAGS += -D DPVS_CFG_PARSER_DEBUG
#CFLAGS += -D NETIF_BONDING_DEBUG
#CFLAGS += $(WERROR_FLAGS)

LDFLAGS += -lcrypto

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

include $(RTE_SDK)/mk/rte.extapp.mk
