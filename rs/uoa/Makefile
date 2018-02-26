obj-m	+= uoa.o

ifeq ($(KERNDIR), )
KDIR	:= /lib/modules/$(shell uname -r)/build
else
KDIR	:= $(KERNDIR)
endif
PWD	:= $(shell pwd)

ccflags-y := -I$(src)/../../include

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean

