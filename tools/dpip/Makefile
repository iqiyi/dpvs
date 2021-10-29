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
# Makefile for dpip
#

TARGET = build/dpip

CFLAGS = -g -O0
CFLAGS += -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes

CFLAGS += -I ../../include
CFLAGS += -I ../keepalived/keepalived/include

LIBS = -lnuma
DEFS = -D DPVS_MAX_LCORE=64

CFLAGS += $(DEFS)

OBJS = dpip.o utils.o route.o addr.o neigh.o link.o vlan.o \
	   qsch.o cls.o tunnel.o ipset.o ipv6.o iftraf.o eal_mem.o ../../src/common.o \
	   ../keepalived/keepalived/check/sockopt.o

all: $(TARGET)

$(TARGET): $(OBJS)
	-mkdir -p ./build/
	gcc $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -rf ./build/ *.o
