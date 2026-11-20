package opa

import (
	"github.com/cosmosdevops/kube-policy-mcp/internal/engines"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// EngineName is the name this adapter registers under.
const EngineName = "opa"

func init() {
	engines.Register(engines.Registration{
		Name:         EngineName,
		Title:        "OPA / Rego",
		Description:  "Evaluates Rego policies with the embedded Open Policy Agent libraries, following Conftest conventions (deny, violation and warn rules; the resource is input).",
		SourceFormat: "A directory of .rego files, optionally with data.json or data.yaml files laid out as an OPA bundle, or a bundle .tar.gz file.",
		Limitations: []string{
			"Rego has no native way to say which resources a policy applies to. Declare custom.kinds or an applies rule, otherwise a policy applies to every kind.",
			"Rego rules do not expose a single condition, so explanations quote the rule title or policy description.",
			"There are no native exceptions. Use pack-level exemptions.",
			"http.send, net.lookup_ip_addr and opa.runtime are removed. Policies that use them do not compile.",
		},
		Module: "github.com/open-policy-agent/opa",
		New:    func() policy.Engine { return New() },
	})
}
