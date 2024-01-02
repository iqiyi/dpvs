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
# Makefile for tools
#
SUBDIRS = keepalived ipvsadm dpip

ifeq ($(CONFIG_DPVS_AGENT), y)
SUBDIRS += healthcheck
SUBDIRS += dpvs-agent
endif

all: config
	for i in $(SUBDIRS); do $(MAKE) -C $$i || exit 1; done

config: keepalived_conf

keepalived_conf:
	if [ ! -f keepalived/Makefile ]; then \
		cd keepalived; \
		if [ ! -f keepalived/configure ]; then \
			./build_setup; \
		fi; \
		./configure; \
		cd -; \
	fi

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean || exit 1; done

install:
	install -m 744 keepalived/bin/keepalived $(INSDIR)/keepalived
	install -m 744 ipvsadm/ipvsadm $(INSDIR)/ipvsadm
	install -m 744 dpip/build/dpip $(INSDIR)/dpip
ifeq ($(CONFIG_DPVS_AGENT), y)
	install -m 744 healthcheck/healthcheck $(INSDIR)/healthcheck
	install -m 744 dpvs-agent/cmd/dpvs-agent-server/dpvs-agent $(INSDIR)/dpvs-agent
endif
