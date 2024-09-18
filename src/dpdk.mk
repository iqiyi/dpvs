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

# If the dpdklib isn't installed to the default location on your system,
# please specify PKG_CONFIG_PATH explicitly as below.
#
# LIBDPDKPC_PATH := /path/to/dpdk/build/lib/pkgconfig

define PKG_CONFIG_ERR_MSG
DPDK library was not found.
If dpdk has installed already, please ensure the libdpdk.pc file could be found by `pkg-config`.
You may fix the problem by setting LIBDPDKPC_PATH (in file src/dpdk.mk) to the path of libdpdk.pc file explicitly
endef

# It's noted that pkg-config version 0.29.2+ is recommended,
# pkg-config 0.27.1 would mess up the ld flags when linking dpvs.
PKGCONFIG_VERSION=$(shell pkg-config --version)
ifeq "v$(PKGCONFIG_VERSION)" "v0.27.1"
$(error "pkg-config version $(PKGCONFIG_VERSION) isn't supported, require 0.29.2+")
endif

ifneq ($(wildcard $(LIBDPDKPC_PATH)),)
CFLAGS += -DALLOW_EXPERIMENTAL_API $(shell PKG_CONFIG_PATH=$(LIBDPDKPC_PATH) pkg-config --cflags libdpdk)
LIBS += $(shell PKG_CONFIG_PATH=$(LIBDPDKPC_PATH) pkg-config --static --libs libdpdk)
else
ifeq ($(shell pkg-config --exists libdpdk && echo 0),0)
CFLAGS += -DALLOW_EXPERIMENTAL_API $(shell pkg-config --cflags libdpdk)
LIBS += $(shell pkg-config --static --libs libdpdk)
else
$(error $(PKG_CONFIG_ERR_MSG))
endif
endif
