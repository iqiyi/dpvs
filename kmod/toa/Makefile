obj-m	+= toa.o

ifeq ($(KERNDIR), )
KDIR	:= /lib/modules/$(shell uname -r)/build
else
KDIR	:= $(KERNDIR)
endif
PWD	:= $(shell pwd)

ccflags-y += -DTOA_IPV6_ENABLE
ccflags-y += -DTOA_NAT64_ENABLE

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

