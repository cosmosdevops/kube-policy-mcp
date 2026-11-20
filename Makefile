BINARY := bin/kube-policy-mcp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/cosmosdevops/kube-policy-mcp/internal/app.Version=$(VERSION)

.PHONY: build build-opa build-kyverno test vet demo

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/kube-policy-mcp

# Single-engine builds. An engine that is left out is not linked at all.
build-opa:
	go build -tags no_kyverno -ldflags "$(LDFLAGS)" -o $(BINARY)-opa ./cmd/kube-policy-mcp

build-kyverno:
	go build -tags no_opa -ldflags "$(LDFLAGS)" -o $(BINARY)-kyverno ./cmd/kube-policy-mcp

test:
	go test ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l cmd internal tests examples)" || (echo "gofmt needed:"; gofmt -l cmd internal tests examples; exit 1)

# Runs the scripted agent workflow against the real MCP server.
demo: build
	go run ./examples/mcp/workflow
