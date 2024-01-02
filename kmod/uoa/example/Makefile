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
# Makefile for example uoa
#

all: udp_serv uperf opp

CFLAGS = -g -O0
CFLAGS += -I ../../../include/ -I ../../../include/conf -I ../

CFLAGS += -D WITH_IPV6_ENABLE

udp_serv: udp_serv.c
	gcc $(CFLAGS) -o udp_serv udp_serv.c

uperf: uperf.c
	gcc $(CFLAGS) -lrt -o uperf uperf.c

opp: opp.c
	gcc $(CFLAGS) -o opp opp.c

clean:
	rm -rf udp_serv uperf opp
