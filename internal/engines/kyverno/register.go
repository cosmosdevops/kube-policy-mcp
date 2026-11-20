package kyverno

import (
	"github.com/cosmosdevops/kube-policy-mcp/internal/engines"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// EngineName is the name this adapter registers under.
const EngineName = "kyverno"

func init() {
	engines.Register(engines.Registration{
		Name:             EngineName,
		Title:            "Kyverno",
		Description:      "Evaluates Kyverno CEL validation policies with the embedded upstream Kyverno engine, including matching, autogen for pod controllers and policy exceptions.",
		SourceFormat:     "A directory of YAML or JSON files holding policies.kyverno.io ValidatingPolicy, NamespacedValidatingPolicy and PolicyException resources.",
		NativeExceptions: "PolicyException resources placed in a Kyverno source.",
		Limitations: []string{
			"Only ValidatingPolicy and NamespacedValidatingPolicy are evaluated. Mutating, generating, deleting and image-validating policies are reported as unknown.",
			"Legacy kyverno.io ClusterPolicy and Policy kinds were removed in Kyverno 1.20 and are reported as unknown.",
			"Policies that use the http library, image registry lookups or resource writes are not run.",
			"Resource lookups only see the submitted manifests and context.resources.",
			"Only the first failing validation of a policy is reported.",
		},
		Module: "github.com/kyverno/kyverno",
		New:    func() policy.Engine { return New() },
	})
}
