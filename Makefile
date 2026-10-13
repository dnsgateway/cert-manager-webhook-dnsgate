#

REGISTRY ?= ghcr.io
USERNAME ?= dnsgateway
HELMREPO ?= $(REGISTRY)/$(USERNAME)/charts

SHA ?= $(shell git describe --match=none --always --abbrev=7 --dirty)
TAG ?= $(shell git describe --tag --always --match v[0-9]\*)

GO_LDFLAGS  := -ldflags "-w -s -X main.version=$(TAG) -X main.commit=$(SHA)"
GOOS        ?= $(shell go env GOOS)
GOARCH      ?= $(shell go env GOARCH)

############
#
# Help Menu
#

define HELP_MENU_HEADER
# Getting Started

To build this project, you must have the following installed:

- git
- make
- golang 1.27+
- golangci-lint

endef

export HELP_MENU_HEADER

.PHONY: help
help: ## This help menu
	@echo "$$HELP_MENU_HEADER"
	@grep -E '^[a-zA-Z0-9%_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

############
#
# Build Abstractions
#

clean: ## Remove build artifacts
	rm -rf bin/

build: ## Build the webhook binary
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath $(GO_LDFLAGS) -o bin/cert-manager-webhook-dnsgate ./cmd

lint: ## Lint Go code
	golangci-lint run --config .golangci.yml

vet: ## Vet Go code
	go vet ./...

unit: ## Run tests with the race detector
	go test -race -count=1 ./...

test: lint unit ## Run lint and unit tests

E2E_TIMEOUT ?= 30m

.PHONY: e2e
e2e: ## Issue a certificate through the webhook deployed in the cluster of $KUBECONFIG (see README)
	go test -tags e2e -count=1 -timeout $(E2E_TIMEOUT) -v ./test/e2e

############

.PHONY: licenses
licenses: ## Check licenses
	go-licenses check ./... --disallowed_types=forbidden,restricted,unknown

.PHONY: conformance
conformance: ## Conformance
	docker run --rm -it -v $(PWD):/src -w /src ghcr.io/siderolabs/conform:v0.1.0-alpha.31 enforce

############
#
# Helm Abstractions
#

helm-unit: ## Lint, render and verify installation safety in both Secret access modes
	helm lint charts/cert-manager-webhook-dnsgate
	helm template dnsgate charts/cert-manager-webhook-dnsgate --namespace cert-manager >/dev/null

helm-login: ## Log into the chart registry using HELM_TOKEN
	@printf '%s' "$$HELM_TOKEN" | helm registry login $(REGISTRY) --username $(USERNAME) --password-stdin

helm-release: helm-unit ## Package, push and sign the OCI chart
	@rm -rf bin/
	@helm package charts/cert-manager-webhook-dnsgate -d bin
	@helm push bin/cert-manager-webhook-dnsgate-*.tgz oci://$(HELMREPO) 2>&1 | tee bin/.digest
	@cosign sign --yes $(COSING_ARGS) $(HELMREPO)/cert-manager-webhook-dnsgate@$$(cat bin/.digest | awk -F "[, ]+" '/Digest/{print $$NF}')

############
#
# Release Abstractions
#

release-check: ## Validate GoReleaser configuration
	goreleaser check

snapshot: ## Build an unpublished release snapshot
	goreleaser release --snapshot --clean

release: ## Build and publish a release
	goreleaser release --clean
