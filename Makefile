BINARY := bin/kube-policy-mcp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/cosmosdevops/kube-policy-mcp/internal/app.Version=$(VERSION)

.PHONY: build build-opa build-vap build-gatekeeper image test vet demo

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/kube-policy-mcp

# Single-engine builds. An engine that is left out is not linked at all.
build-opa:
	go build -tags "no_vap no_gatekeeper" -ldflags "$(LDFLAGS)" -o $(BINARY)-opa ./cmd/kube-policy-mcp

build-vap:
	go build -tags "no_opa no_gatekeeper" -ldflags "$(LDFLAGS)" -o $(BINARY)-vap ./cmd/kube-policy-mcp

# Gatekeeper is built on the OPA and Kubernetes libraries, so they stay linked.
build-gatekeeper:
	go build -tags "no_opa no_vap" -ldflags "$(LDFLAGS)" -o $(BINARY)-gatekeeper ./cmd/kube-policy-mcp

# Container image; see deploy/compose.yaml.
image:
	docker build --build-arg VERSION=$(VERSION) -t kube-policy-mcp:local .

test:
	go test ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l cmd internal tests examples)" || (echo "gofmt needed:"; gofmt -l cmd internal tests examples; exit 1)

# Runs the scripted agent workflow against the real MCP server.
demo: build
	go run ./examples/mcp/workflow
