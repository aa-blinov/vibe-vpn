GO      ?= go
BIN     := bin/vibe-vpn
PKG     := ./cmd/vpn
VERSION ?= 0.1.0
PREFIX  ?= /usr/local
DESTDIR ?=

.PHONY: all build install vet fmt test cover integration clean run-server run-client

all: build

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(BIN) $(PKG)

vet:
	$(GO) vet ./...

fmt:
	gofmt -w $$($(GO) list -f '{{.Dir}}' ./... | xargs -I{} find {} -name '*.go')

test:
	$(GO) test -count=1 ./internal/...

cover:
	$(GO) test -count=1 -cover ./internal/...

# Full end-to-end integration test: real TUN devices inside a network
# namespace. Requires root, iproute2, nftables and /dev/net/tun.
integration: build
	sudo env VPN_INTEGRATION=1 VPN_BIN=$$(pwd)/$(BIN) $(GO) test ./test/integration/ -v -count=1

# Install the binary, systemd units and example configs.
install: build
	install -d $(DESTDIR)$(PREFIX)/bin \
		$(DESTDIR)$(PREFIX)/lib/systemd/system \
		$(DESTDIR)/etc/vibe-vpn
	install -m 755 $(BIN) $(DESTDIR)$(PREFIX)/bin/vibe-vpn
	sed -e 's|@BIN@|$(PREFIX)/bin/vibe-vpn|' -e 's|@CONFIG@|/etc/vibe-vpn/server.yaml|' \
		deploy/vibe-vpn-server.service > $(DESTDIR)$(PREFIX)/lib/systemd/system/vibe-vpn-server.service
	sed -e 's|@BIN@|$(PREFIX)/bin/vibe-vpn|' -e 's|@CONFIG@|/etc/vibe-vpn/client.yaml|' \
		deploy/vibe-vpn-client.service > $(DESTDIR)$(PREFIX)/lib/systemd/system/vibe-vpn-client.service
	install -m 600 configs/server.yaml.example $(DESTDIR)/etc/vibe-vpn/server.yaml.example
	install -m 600 configs/client.yaml.example $(DESTDIR)/etc/vibe-vpn/client.yaml.example
	@echo "installed. copy configs to /etc/vibe-vpn/ and enable a service:"
	@echo "  sudo systemctl enable --now vibe-vpn-server"

clean:
	rm -rf bin

run-server: build
	sudo ./$(BIN) server --config server.yaml

run-client: build
	sudo ./$(BIN) client --config client.yaml
