TARGET := dpvs-agent

GO ?= go
LD_FLAGS = -ldflags="-s -w -X main.buildVersion=$(git rev-parse --short HEAD)"
GO_BUILD = CGO_ENABLED=0 $(GO) build $(LD_FLAGS)
GO_CLEAN = $(GO) clean
INSTALL = install
RM = rm

.PHONY: all $(TARGET) clean install

all: $(TARGET)

$(TARGET):
	-$(GO) mod tidy
	$(GO_BUILD) -o $@

clean:
	$(GO_CLEAN)
	-$(RM) $(TARGET)

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(INSDIR)
	$(INSTALL) -m 0744 $(TARGET) $(INSDIR)

uninstall:
	-$(RM) -f $(TARGET) $(INSDIR)/$(TARGET)
