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
# Makefile for dpvs (DPVS main program).
#

TARGET := dpvs

ifneq ("$(wildcard VERSION)","")
    VERSION_STRING := $(shell ./VERSION)
else
    VERSION_STRING := $(shell git describe --tags --always)
endif

DATE_STRING := $(shell date +%Y.%m.%d.%H:%M:%S)

# same path of THIS Makefile
SRCDIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

# Addtional libs below are needed when using dynamic link.
LIBS += -lpthread -lnuma -lrt -lm -ldl -lcrypto

ifeq ($(shell pkg-config --exists libssl && echo 0),0)
CFLAGS += $(shell pkg-config --cflags libssl)
LIBS += $(shell pkg-config --static --libs libssl)
endif

include $(SRCDIR)/config.mk
include $(SRCDIR)/dpdk.mk

INCDIRS += -I $(SRCDIR)/../include

# for dpvs main program.
CFLAGS += -D __DPVS__ -DDPVS_VERSION=\"$(VERSION_STRING)\" -DDPVS_BUILD_DATE=\"$(DATE_STRING)\"

CFLAGS += -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes -mcmodel=medium

ifeq ($(shell test $(GCC_VERSION) -ge 70 && echo 1), 1)
	CFLAGS += -Wno-format-truncation
	CFLAGS += -Wno-stringop-truncation
	CFLAGS += -Wno-address-of-packed-member
	CFLAGS += -Wstringop-overflow=0
endif

ifneq ($(CONFIG_DEBUG), y)
	CFLAGS += -O3
else
	CFLAGS += -g -O0 -D DEBUG
	CFLAGS += -rdynamic
endif


CFLAGS += $(INCDIRS)

OBJS := $(shell find $(SRCDIR) -name '*.c' | sort)
OBJS := $(patsubst %.c,%.o,$(OBJS))

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "  $(notdir $@)"
	$(Q)$(CC) $(CFLAGS) $^ $(LIBS) -o $@

%.o: %.c
	@echo "  $(notdir $@)"
	$(Q)$(CC) -c $(CFLAGS) $< -o $@

clean:
	find $(SRCDIR) -name '*.o' | xargs rm -f
	rm -f ./$(TARGET)

install:
	install -m 744 $(TARGET) $(INSDIR)
