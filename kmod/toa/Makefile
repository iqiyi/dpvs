obj-m	+= toa.o

ifeq ($(KERNDIR), )
KDIR	:= /lib/modules/$(shell uname -r)/build
else
KDIR	:= $(KERNDIR)
endif
PWD	:= $(shell pwd)

ccflags-y += -DTOA_IPV6_ENABLE
ccflags-y += -DTOA_NAT64_ENABLE

# Feature probe: does the target kernel's inet_connection_sock_af_ops.syn_recv_sock
# carry the opt_child_init 7th arg (upstream CVE-2026-43198 / commit 858d2a4f67ff,
# merged in v7.0; EL10 backported since 6.12.0-211.28.1.el10_2)? Probe the kernel
# header rather than a version macro: RHEL_RELEASE_CODE has only minor granularity
# and cannot express the z-stream (211.28.1) boundary, and the same change will land
# in Debian/Ubuntu 6.12.y LTS and mainline v7.0+.
ifneq ($(wildcard $(KDIR)/include/net/inet_connection_sock.h),)
ifneq ($(shell grep -c 'opt_child_init' $(KDIR)/include/net/inet_connection_sock.h 2>/dev/null),0)
ccflags-y += -DTOA_SYN_RECV_SOCK_HAS_OPT_CHILD_INIT
endif
endif

ifeq ($(DEBUG), 1)
ccflags-y += -g -O0
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean

install:
	if [ -d "$(INSDIR)" ]; then \
		install -m 664 toa.ko $(INSDIR)/toa.ko; \
	fi

