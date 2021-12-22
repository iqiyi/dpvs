#
#      ipvsadm - IP Virtual Server ADMinistration program
#                for IPVS NetFilter Module in kernel 2.4
#
#      Version: $Id: Makefile 77 2011-02-08 00:23:51Z wensong $
#
#      Authors: Wensong Zhang <wensong@linux-vs.org>
#               Peter Kese <peter.kese@ijs.si>
#
#      This file:
#
#      ChangeLog
#
#      Wensong        :   Modified the Makefile and the spec files so
#                     :   that rpms can be created with ipvsadm alone
#      P.Copeland     :   Modified the Makefile and the spec files so
#                     :   that it is possible to create rpms on the fly
#                     :   using 'make rpms'
#                     :   Also added NAME, VERSION and RELEASE numbers to
#                     :   the Makefile
#      Horms          :   Updated to add config_stream.c dynamic_array.c
#                     :   Added autodetection of libpot
#                     :   Added BUILD_ROOT support
#      Wensong        :   Changed the OBJS according to detection
#      Ratz           :   Fixed to use the correct CFLAGS on sparc64
#

NAME		= ipvsadm
VERSION		= $(shell cat VERSION)
RELEASE		= 1
SCHEDULERS	= "$(shell cat SCHEDULERS)"
PE_LIST		= "$(shell cat PERSISTENCE_ENGINES)"
PROGROOT	= $(shell basename `pwd`)
ARCH		= $(shell uname -m)
RPMSOURCEDIR	= $(shell rpm --eval '%_sourcedir')
RPMSPECDIR	= $(shell rpm --eval '%_specdir')

CC		= gcc
INCLUDE		=
SBIN		= $(RPM_BUILD_ROOT)/sbin
MANDIR		= usr/man
MAN		= $(RPM_BUILD_ROOT)/$(MANDIR)/man8
INIT		= $(RPM_BUILD_ROOT)/etc/rc.d/init.d
MKDIR		= mkdir
INSTALL		= install
STATIC_LIBS	= ../keepalived/keepalived/check/libcheck.a
DPVSDEPS    = ../../src/common.o

ifeq "${ARCH}" "sparc64"
    CFLAGS = -Wall -Wunused -Wstrict-prototypes -g -m64 -pipe -mcpu=ultrasparc -mcmodel=medlow
else
    CFLAGS = -Wall -Wunused -Wstrict-prototypes -g
endif

CFLAGS += -I ../../include


#####################################
# No servicable parts below this line

RPMBUILD = $(shell				\
	if [ -x /usr/bin/rpmbuild ]; then	\
		echo "/usr/bin/rpmbuild";	\
	else					\
		echo "/bin/rpm";		\
	fi )

#ifeq (,$(FORCE_GETOPT))
#LIB_SEARCH = /lib64 /usr/lib64 /usr/local/lib64 /lib /usr/lib /usr/local/lib
#POPT_LIB = $(shell for i in $(LIB_SEARCH); do \
#  if [ -f $$i/libpopt.a ]; then \
#    if nm $$i/libpopt.a | fgrep -q poptGetContext; then \
#	echo "-lpopt"; \
#	break; \
#    fi; \
#  fi; \
#done)
#endif
POPT_LIB = -lpopt 

ifneq (,$(POPT_LIB))
POPT_DEFINE = -DHAVE_POPT
endif

OBJS		= ipvsadm.o config_stream.o dynamic_array.o
LIBS		= $(POPT_LIB) -lnuma
DEFINES		= -DVERSION=\"$(VERSION)\" -DSCHEDULERS=\"$(SCHEDULERS)\" \
		  -DPE_LIST=\"$(PE_LIST)\" $(POPT_DEFINE)
DEFINES		+= $(shell if [ ! -f ../ip_vs.h ]; then	\
		     echo "-DHAVE_NET_IP_VS_H"; fi;)


.PHONY	= all clean install dist distclean rpm rpms

all:            ipvsadm

ipvsadm:	$(OBJS) $(STATIC_LIBS)
		$(CC) $(CFLAGS) -o $@ $^ $(DPVSDEPS) $(LIBS)

install:        all
		if [ ! -d $(SBIN) ]; then $(MKDIR) -p $(SBIN); fi
		$(INSTALL) -m 0755 ipvsadm $(SBIN)
		$(INSTALL) -m 0755 ipvsadm-save $(SBIN)
		$(INSTALL) -m 0755 ipvsadm-restore $(SBIN)
		[ -d $(MAN) ] || $(MKDIR) -p $(MAN)
		$(INSTALL) -m 0644 ipvsadm.8 $(MAN)
		$(INSTALL) -m 0644 ipvsadm-save.8 $(MAN)
		$(INSTALL) -m 0644 ipvsadm-restore.8 $(MAN)
		[ -d $(INIT) ] || $(MKDIR) -p $(INIT)
		$(INSTALL) -m 0755 ipvsadm.sh $(INIT)/ipvsadm

clean:
		rm -f ipvsadm $(NAME).spec $(NAME)-$(VERSION).tar.gz
		rm -rf debian/tmp
		find . -name '*.[ao]' -o -name "*~" -o -name "*.orig" \
		  -o -name "*.rej" -o -name core | xargs rm -f

distclean:	clean

dist:		distclean
		sed -e "s/@@VERSION@@/$(VERSION)/g" \
		    -e "s/@@RELEASE@@/$(RELEASE)/g" \
		    < ipvsadm.spec.in > ipvsadm.spec
		rm -f $(NAME)-$(VERSION)
		ln -s . $(NAME)-$(VERSION)
		tar czvf $(NAME)-$(VERSION).tar.gz			\
		    --exclude CVS --exclude .svn --exclude TAGS		\
		    --exclude $(NAME)-$(VERSION)/$(NAME)-$(VERSION)	\
		    --exclude $(NAME)-$(VERSION).tar.gz			\
		    $(NAME)-$(VERSION)/*
		rm -f $(NAME)-$(VERSION)

rpms:		dist
		cp $(NAME)-$(VERSION).tar.gz $(RPMSOURCEDIR)/
		cp $(NAME).spec $(RPMSPECDIR)/
		$(RPMBUILD) -ba $(RPMSPECDIR)/$(NAME).spec

srpm:		dist
		cp $(NAME)-$(VERSION).tar.gz $(RPMSOURCEDIR)/
		cp $(NAME).spec $(RPMSPECDIR)/
		$(RPMBUILD) -bs $(RPMSPECDIR)/$(NAME).spec

deb:		debs

debs:
		dpkg-buildpackage

%.o:	%.c
		$(CC) $(CFLAGS) $(INCLUDE) $(DEFINES) -c -o $@ $<
