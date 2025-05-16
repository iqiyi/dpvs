TARGET := healthcheck

GO ?= go
LD_FLAGS = -ldflags="-s -w -X main.buildVersion=$(git rev-parse --short HEAD)"
GO_BUILD = CGO_ENABLED=0 $(GO) build $(LD_FLAGS)
GO_CLEAN = $(GO) clean

.PHONY: all $(TARGET) clean

all: $(TARGET)

$(TARGET): go-proxy
	-$(GO) mod tidy
	$(GO) vet
	$(GO_BUILD) -o $@

go-proxy:
	$(GO) env -w GOPROXY=https://goproxy.cn,direct

clean:
	$(GO_CLEAN)

MODULE_NAME := $(shell grep '^module ' go.mod | awk '{print $$2}')
GO_PATH := $(shell $(GO) env GOPATH)
code-gen: $(GO_PATH)/bin/deepcopy-gen
	$(GO_PATH)/bin/deepcopy-gen --alsologtostderr -i $(MODULE_NAME)/pkg/manager/ -O zz_deepcopy_generated --go-header-file=license.txt --trim-path-prefix=$(MODULE_NAME)
	$(GO_PATH)/bin/deepcopy-gen --alsologtostderr -i $(MODULE_NAME)/pkg/comm/ -O zz_deepcopy_generated --go-header-file=license.txt --trim-path-prefix=$(MODULE_NAME)

$(GO_PATH)/bin/deepcopy-gen:
	go install k8s.io/code-generator/cmd/deepcopy-gen@v0.29.12

license: license.txt
ifeq ($(shell addlicense 2>&1|grep Usage),)
	$(error "`addlicense` command not found. You can install it with `go install github.com/google/addlicense`")
endif
	-addlicense -f license.txt -v .
