TARGET := healthcheck

GO ?= go
LD_FLAGS = -ldflags="-s -w -X main.buildVersion=$(git rev-parse --short HEAD)"
GO_BUILD = CGO_ENABLED=0 $(GO) build $(LD_FLAGS)
GO_CLEAN = $(GO) clean

.PHONY: all $(TARGET) clean

all: $(TARGET)

$(TARGET):
	-$(GO) mod tidy
	$(GO_BUILD) -o $@

clean:
	$(GO_CLEAN)

license: license.txt
ifeq ($(shell addlicense 2>&1|grep Usage),)
	$(error "`addlicense` command not found. You can install it with `go install github.com/google/addlicense`")
endif
	-addlicense -f license.txt -v .
