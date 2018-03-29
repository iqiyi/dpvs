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
# Makefile for dpvs (DPVS main program).
#

#DEBUG := 1		# enable for debug

TARGET := dpvs

VERSION_STRING := $(shell ./VERSION)
DATE_STRING := $(shell date +%Y.%m.%d.%H:%M:%S)

# same path of THIS Makefile
SRCDIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

include $(SRCDIR)/dpdk.mk
include $(SRCDIR)/config.mk

INCDIRS += -I $(SRCDIR)/../include

# for dpvs main program.
CFLAGS += -D __DPVS__ -DDPVS_VERSION=\"$(VERSION_STRING)\" -DDPVS_BUILD_DATE=\"$(DATE_STRING)\" 

CFLAGS += -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes -mcmodel=medium

ifeq ($(DEBUG),)
	CFLAGS += -O3
else
	CFLAGS += -g -O0 -D DEBUG
endif

LIBS += -lpthread -lnuma

CFLAGS += $(INCDIRS) $(LIBS)

OBJS := $(shell find $(SRCDIR) -name '*.c' | sort)
OBJS := $(patsubst %.c,%.o,$(OBJS))

all: $(TARGET)

$(TARGET): $(OBJS)
	@$(CC) $(CFLAGS) $^ -o $@
	@echo "  $(notdir $@)"

%.o: %.c
	@$(CC) -c $(CFLAGS) $< -o $@
	@echo "  $(notdir $@)"

clean:
	find $(SRCDIR) -name '*.o' | xargs rm -f
	rm -f ./$(TARGET)

install:
	install -m 744 $(TARGET) $(INSDIR)
