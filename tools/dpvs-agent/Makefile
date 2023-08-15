MAKE	= make
SUBDIRS = cmd/dpvs-agent-server
INSDIR  = $(PWD)/bin
export INSDIR

OPENAPISPEC = dpvs-agent-api.yaml

SWAGGER_REQUIRED_VERSION := v0.30.4
SWAGGER_VERSION := $(shell swagger version 2>/dev/null | awk '/^version:/{print $$2}')

all:
	for i in $(SUBDIRS); do $(MAKE) -C $$i || exit 1; done

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean || exit 1; done

install:all
	-mkdir -p $(INSDIR)
	for i in $(SUBDIRS); do $(MAKE) -C $$i install || exit 1; done

uninstall:
	for i in $(SUBDIRS); do $(MAKE) -C $$i uninstall || exit 1; done

openapi: $(OPENAPISPEC)
ifneq ($(SWAGGER_VERSION),$(SWAGGER_REQUIRED_VERSION))
	$(error Golang `swagger` $(SWAGGER_REQUIRED_VERSION) is not found. You can install it with 'go get github.com/go-swagger/go-swagger@$(SWAGGER_REQUIRED_VERSION)' or download it from 'https://github.com/go-swagger/go-swagger/releases/download/$(SWAGGER_REQUIRED_VERSION)')
endif
	swagger generate server -A dpvs-agent -f $<
	git checkout cmd/dpvs-agent-server/main.go

license:
ifeq ($(shell addlicense 2>&1|grep Usage),)
	$(error `addlicense` command not found. You can install it with 'go install github.com/google/addlicense')
endif
	@addlicense -check -c "IQiYi Inc." -l apache -ignore dpvs/** . || /bin/true
	-addlicense -f license.txt -v .
