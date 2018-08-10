DATE_TIME := $(shell date -u "+%Y-%m-%dT%H:%M:%SZ")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2> /dev/null)
GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null)
GIT_TAG := $(shell git describe --exact-match --tags 2> /dev/null)
GIT_LAST_TAG := $(shell git describe --abbrev=0 --tags 2> /dev/null)

DATA_DIR := ./data

HOST_KEY_DIR := $(DATA_DIR)/server

$(HOST_KEY_DIR)/ssh_host_dsa_key:
	ssh-keygen -t dsa -f $(HOST_KEY_DIR)/ssh_host_dsa_key -N "" -C "SSH Gateway"
$(HOST_KEY_DIR)/ssh_host_ed25519_key:
	ssh-keygen -t ed25519 -f $(HOST_KEY_DIR)/ssh_host_ed25519_key -N "" -C "SSH Gateway"
$(HOST_KEY_DIR)/ssh_host_ecdsa_key:
	ssh-keygen -t ecdsa -f $(HOST_KEY_DIR)/ssh_host_ecdsa_key -N "" -C "SSH Gateway"
$(HOST_KEY_DIR)/ssh_host_rsa_key:
	ssh-keygen -t rsa -f $(HOST_KEY_DIR)/ssh_host_rsa_key -N "" -C "SSH Gateway"

.PHONY: host_keys

host_keys: $(HOST_KEY_DIR)/ssh_host_dsa_key $(HOST_KEY_DIR)/ssh_host_ed25519_key $(HOST_KEY_DIR)/ssh_host_ecdsa_key $(HOST_KEY_DIR)/ssh_host_rsa_key

.PHONY: dev-deps

dev-deps:
	go get -u golang.org/x/vgo

.PHONY: build

build:
	vgo build -ldflags "-X main.version=$(GIT_LAST_TAG) -X main.commit=$(GIT_COMMIT) -X main.compiled=$(DATE_TIME)" -o dist/ssh-gateway-$(shell go env GOOS)-$(shell go env GOARCH)$(shell go env GOEXE) ./cmd/ssh-gateway
