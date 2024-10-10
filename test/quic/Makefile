TARGETS := quic-client quic-server h3client h3server

GO ?= go
LD_FLAGS = -ldflags="-s -w"
GO_BUILD = CGO_ENABLED=0 $(GO) build $(LD_FLAGS)
RM ?= rm


.PHONY: all $(TARGET) clean version_notes

all: version_notes $(TARGETS)

quic-client: client/quic-client.go
	$(GO_BUILD) -o $@ $<

quic-server: server/quic-server.go
	$(GO_BUILD) -o $@ $<

h3client: http3/h3client/h3client.go
	$(GO_BUILD) -o $@ $<

h3server: http3/h3server/h3server.go
	$(GO_BUILD) -o $@ $<

clean:
	@-$(RM) $(TARGETS)

version_notes:
	$(info "Notes: $(shell go version), v1.21+ is required")
