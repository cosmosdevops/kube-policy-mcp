package vap

import (
	"github.com/cosmosdevops/kube-policy-mcp/internal/engines"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// EngineName is the name this adapter registers under.
const EngineName = "vap"

func init() {
	engines.Register(engines.Registration{
		Name:         EngineName,
		Title:        "Kubernetes ValidatingAdmissionPolicy",
		Description:  "Evaluates Kubernetes ValidatingAdmissionPolicy resources and their bindings with the embedded Kubernetes API server CEL admission code, including matching, match conditions, variables and parameters.",
		SourceFormat: "A directory of YAML or JSON files holding admissionregistration.k8s.io ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding resources. Any other resource in the directory can be used as a policy parameter.",
		Limitations: []string{
			"A policy is only enforced through a binding. A policy with no binding in the same source is reported as unknown.",
			"There is no autogen: a policy that matches pods does not apply to Deployments or other controllers unless it matches them itself.",
			"Policies that use the authorizer variable are not run, because RBAC needs a live cluster.",
			"Parameter objects must be in the policy source, the submitted manifests or context.resources. A parameter that is not found gives unknown.",
			"Expressions are not type-checked against resource schemas. A wrong field name shows up as an error at evaluation, not at load.",
			"There are no native exceptions. Use matchConditions, excludeResourceRules or pack-level exemptions.",
			"MutatingAdmissionPolicy is not evaluated and is reported as unknown.",
		},
		Module: "k8s.io/apiserver",
		New:    func() policy.Engine { return New() },
	})
}
