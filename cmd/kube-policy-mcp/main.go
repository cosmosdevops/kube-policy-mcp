// Command kube-policy-mcp evaluates Kubernetes manifests against
// organisational policies, as an MCP server or from the command line.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/cosmosdevops/kube-policy-mcp/internal/cli"

	// The engine adapters register themselves when linked in. This import
	// is the only place that decides which engines the binary contains.
	_ "github.com/cosmosdevops/kube-policy-mcp/internal/engines/builtin"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
