// Package remediation attaches deterministic fix guidance to findings. It
// only reuses text the policy or the engine provided. It never writes patches
// and never changes manifests.
package remediation

import (
	"fmt"
	"strings"

	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// Attach fills f.Remediation when the finding needs action and has none yet.
func Attach(f *findings.Finding, p policy.Policy) {
	switch f.Status {
	case findings.StatusFail, findings.StatusWarning:
		if f.Remediation != nil {
			f.Remediation.Docs = p.Docs
			return
		}
		switch {
		case p.Remediation != "":
			f.Remediation = &findings.Remediation{Description: p.Remediation, Source: "policy-metadata"}
		case p.Description != "":
			// No fix is declared, so state the requirement instead of guessing one.
			f.Remediation = &findings.Remediation{Description: "No fix is declared by the policy. Requirement: " + p.Description, Source: "policy-description"}
		case f.Message != "":
			f.Remediation = &findings.Remediation{Description: "No fix is declared by the policy. Change the resource so this no longer holds: " + f.Message, Source: "derived-from-message"}
		}
		if f.Remediation != nil {
			f.Remediation.Docs = p.Docs
		}
	case findings.StatusUnknown:
		if f.Remediation != nil || len(f.MissingContext) == 0 {
			return
		}
		f.Remediation = &findings.Remediation{
			Description: fmt.Sprintf("Evaluate again and supply the missing context: %s. %s", strings.Join(f.MissingContext, ", "), contextHint(f.MissingContext)),
			Source:      "missing-context",
		}
	}
}

func contextHint(keys []string) string {
	var hints []string
	seen := map[string]bool{}
	add := func(h string) {
		if !seen[h] {
			seen[h] = true
			hints = append(hints, h)
		}
	}
	for _, k := range keys {
		switch {
		case strings.HasPrefix(k, "namespace"):
			add("Set context.namespace (name and labels) for the target namespace.")
		case k == "resources":
			add("Add the looked-up objects (for example ConfigMaps) to context.resources.")
		case strings.HasPrefix(k, "user"):
			add("Set context.user (username and groups).")
		case k == "operation":
			add("Set context.operation.")
		case k == "kubernetesVersion":
			add("Set context.kubernetesVersion.")
		case strings.HasPrefix(k, "variables."):
			add("Set the named entry in context.variables.")
		case strings.HasPrefix(k, "data"):
			add("Set the named entry in context.data.")
		}
	}
	return strings.Join(hints, " ")
}
