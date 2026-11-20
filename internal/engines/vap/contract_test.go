package vap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cosmosdevops/kube-policy-mcp/internal/engines"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy/enginetest"
)

// TestEngineContract runs the shared adapter contract against the example
// policy library and every example manifest.
func TestEngineContract(t *testing.T) {
	examples := filepath.Join("..", "..", "..", "examples")
	var manifests []byte
	for _, f := range []string{"compliant/web.yaml", "noncompliant/web.yaml", "multi/app.yaml", "exemptions/node-exporter.yaml", "production/checkout.yaml"} {
		data, err := os.ReadFile(filepath.Join(examples, "manifests", f))
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, append([]byte("\n---\n"), data...)...)
	}
	for _, source := range []string{"policies/vap", "policies/production/vap"} {
		t.Run(source, func(t *testing.T) {
			enginetest.Run(t, New(), filepath.Join(examples, source), string(manifests))
		})
	}
}

// TestRegistration checks that linking the package registers the adapter.
func TestRegistration(t *testing.T) {
	if !engines.IsRegistered(EngineName) {
		t.Fatalf("%s did not register itself", EngineName)
	}
	for _, r := range engines.Registered() {
		if r.Name != EngineName {
			continue
		}
		eng := r.New()
		info := r.Describe(eng, true)
		if eng.Name() != EngineName || info.Title == "" || info.Description == "" || info.SourceFormat == "" || len(info.Limitations) == 0 || len(info.PolicyTypes) == 0 {
			t.Errorf("incomplete registration: %+v", info)
		}
	}
}
