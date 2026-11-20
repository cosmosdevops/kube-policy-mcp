// Package policy defines the engine-neutral policy model and the interface
// every policy engine adapter implements.
package policy

import (
	"context"
	"slices"

	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
)

// Enforcement actions shared by all engines.
const (
	EnforceDeny  = "deny"
	EnforceWarn  = "warn"
	EnforceAudit = "audit"
)

// Rule is one rule or validation inside a policy.
type Rule struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	Enforcement string `json:"enforcement,omitempty"`
	// Expression is the native condition, when the engine exposes one.
	Expression string `json:"expression,omitempty"`
	Message    string `json:"message,omitempty"`
}

// ExceptionInfo describes a native policy exception that targets a policy.
type ExceptionInfo struct {
	Name       string   `json:"name"`
	Conditions []string `json:"conditions,omitempty"`
	SourcePath string   `json:"sourcePath,omitempty"`
}

// Policy is the metadata for one policy. Fields are filled only from what
// the policy itself declares; nothing is invented.
type Policy struct {
	// ID is "<engine>/<native name>" and is unique within a resolved pack.
	ID     string `json:"id"`
	Name   string `json:"name"`
	Engine string `json:"engine"`
	// Type is the engine's native policy type.
	Type        string `json:"type"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Version     string `json:"version,omitempty"`
	Enforcement string `json:"enforcement,omitempty"`
	// Kinds lists the resource kinds the policy applies to. Empty means the
	// policy does not declare this and may apply to any kind.
	Kinds []string `json:"kinds,omitempty"`
	// Match is the native matching criteria, when the engine has them.
	Match any    `json:"match,omitempty"`
	Rules []Rule `json:"rules,omitempty"`
	// RequiredContext lists context the policy needs (see evalctx.Missing).
	RequiredContext []string        `json:"requiredContext,omitempty"`
	Remediation     string          `json:"remediation,omitempty"`
	Docs            []string        `json:"docs,omitempty"`
	Exceptions      []ExceptionInfo `json:"exceptions,omitempty"`
	SourcePath      string          `json:"sourcePath"`
	// Pack is the pack whose source supplied this policy.
	Pack string `json:"pack,omitempty"`
	// Supported is false when the policy cannot be evaluated offline. Such
	// policies still take part in evaluation and yield unknown or error.
	Supported bool `json:"supported"`
	// Problem explains why the policy is unsupported or failed to load.
	Problem string `json:"problem,omitempty"`
	// LoadError is true when Problem is a load or compile failure.
	LoadError bool `json:"loadError,omitempty"`
	// Raw is the original policy definition.
	Raw string `json:"-"`
	// Native is engine-private state.
	Native any `json:"-"`
}

// AppliesToKind reports whether the policy may apply to a kind, based on its
// declared kinds.
func (p Policy) AppliesToKind(kind string) bool {
	return len(p.Kinds) == 0 || slices.Contains(p.Kinds, kind) || slices.Contains(p.Kinds, "*")
}

// LoadResult is what an engine found in one policy source.
type LoadResult struct {
	Policies []Policy
	// Warnings are non-fatal notes, such as ignored files.
	Warnings []string
}

// Limits bounds policy input.
type Limits struct {
	MaxPolicyBytes int64
	MaxPolicyFiles int
}

// Engine is the contract for a policy engine adapter.
//
// Evaluate must return at least one finding for every (policy, resource)
// pair, using not_applicable, unknown or error where it cannot decide. The
// evaluator turns any missing pair into an error so that a silent gap can
// never look like compliance.
type Engine interface {
	Name() string
	SupportedPolicyTypes() []string
	// LoadSource discovers the policies under a local path.
	LoadSource(ctx context.Context, path string, lim Limits) (LoadResult, error)
	// ValidatePolicy checks that a loaded policy compiles.
	ValidatePolicy(ctx context.Context, p Policy) error
	Evaluate(ctx context.Context, resources []manifests.Resource, policies []Policy, ec evalctx.Context) ([]findings.Finding, error)
}
