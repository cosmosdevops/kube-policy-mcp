// Package enginetest holds the contract tests every engine adapter must
// pass. They check the promises the core relies on, so that a new adapter
// can be added without reading the core.
//
// An adapter's own test calls Run with a directory of its policies and some
// manifests. The policies should produce a mix of results.
package enginetest

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Run checks an adapter against the engine contract.
//
//   - source is a policy source the adapter can load.
//   - manifestYAML holds one or more resources to evaluate.
func Run(t *testing.T, eng policy.Engine, source, manifestYAML string) {
	t.Helper()
	ctx := context.Background()

	name := eng.Name()
	if !nameRE.MatchString(name) {
		t.Fatalf("engine name %q must be lower-case letters, digits and dashes", name)
	}
	if len(eng.SupportedPolicyTypes()) == 0 {
		t.Error("SupportedPolicyTypes is empty")
	}

	// A source that does not exist is an error, never an empty policy list.
	if _, err := eng.LoadSource(ctx, filepath.Join(t.TempDir(), "absent"), policy.Limits{}); err == nil {
		t.Error("loading a missing source must fail")
	}

	first, err := eng.LoadSource(ctx, source, policy.Limits{})
	if err != nil {
		t.Fatalf("LoadSource: %v", err)
	}
	if len(first.Policies) == 0 {
		t.Fatal("the test source has no policies")
	}
	again, err := eng.LoadSource(ctx, source, policy.Limits{})
	if err != nil {
		t.Fatalf("LoadSource (second time): %v", err)
	}
	if got, want := ids(again.Policies), ids(first.Policies); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("loading is not deterministic:\n%v\n%v", want, got)
	}
	if !sort.StringsAreSorted(ids(first.Policies)) {
		t.Errorf("policies must be sorted by id: %v", ids(first.Policies))
	}

	known := map[string]policy.Policy{}
	for _, p := range first.Policies {
		if p.Engine != name {
			t.Errorf("policy %s: engine is %q, want %q", p.ID, p.Engine, name)
		}
		if !strings.HasPrefix(p.ID, name+"/") || p.ID == name+"/" {
			t.Errorf("policy id %q must start with %q", p.ID, name+"/")
		}
		if _, dup := known[p.ID]; dup {
			t.Errorf("policy id %q is returned twice", p.ID)
		}
		known[p.ID] = p
		if p.SourcePath == "" {
			t.Errorf("policy %s has no source path", p.ID)
		}
		if p.Type == "" {
			t.Errorf("policy %s has no type", p.ID)
		}
		// A policy that cannot be evaluated must say why, and must not validate.
		verr := eng.ValidatePolicy(ctx, p)
		switch {
		case p.Supported && p.Problem != "":
			t.Errorf("policy %s is marked supported but has a problem: %s", p.ID, p.Problem)
		case p.Supported && verr != nil:
			t.Errorf("policy %s is marked supported but does not validate: %v", p.ID, verr)
		case !p.Supported && p.Problem == "":
			t.Errorf("policy %s is not supported but gives no reason", p.ID)
		case !p.Supported && verr == nil:
			t.Errorf("policy %s is not supported but validates", p.ID)
		}
		for _, r := range p.Rules {
			if r.ID == "" {
				t.Errorf("policy %s has a rule without an id", p.ID)
			}
		}
	}

	resources, err := manifests.Parse([]byte(manifestYAML), "contract", manifests.Limits{})
	if err != nil {
		t.Fatalf("test manifests: %v", err)
	}
	var ec evalctx.Context
	if err := ec.Normalize(); err != nil {
		t.Fatal(err)
	}
	before := snapshot(resources)
	results, err := eng.Evaluate(ctx, resources, first.Policies, ec)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Evaluation must not change what was submitted.
	if snapshot(resources) != before {
		t.Error("Evaluate modified the submitted resources")
	}

	refs := map[string]bool{}
	for _, r := range resources {
		refs[r.Ref().Key()] = true
	}
	valid := map[findings.Status]bool{}
	for _, s := range findings.AllStatuses {
		valid[s] = true
	}
	covered := map[string]bool{}
	for _, f := range results {
		if f.Engine != name {
			t.Errorf("finding for %s has engine %q, want %q", f.Policy, f.Engine, name)
		}
		p, ok := known[f.Policy]
		if !ok {
			t.Errorf("finding refers to unknown policy %q", f.Policy)
			continue
		}
		if !refs[f.Resource.Key()] {
			t.Errorf("finding for %s refers to a resource that was not submitted: %+v", f.Policy, f.Resource)
		}
		if !valid[f.Status] {
			t.Errorf("finding for %s has unknown status %q", f.Policy, f.Status)
		}
		covered[f.Policy+"\x00"+f.Resource.Key()] = true

		// What cannot be evaluated can never pass, fail or warn.
		if !p.Supported {
			switch f.Status {
			case findings.StatusPass, findings.StatusFail, findings.StatusWarning, findings.StatusExempted:
				t.Errorf("policy %s cannot be evaluated but produced %q", p.ID, f.Status)
			}
		}
		switch f.Status {
		case findings.StatusFail, findings.StatusWarning, findings.StatusUnknown, findings.StatusError:
			if f.Message == "" {
				t.Errorf("%s finding for %s has no message", f.Status, f.Policy)
			}
		case findings.StatusExempted:
			if f.Exemption == nil || f.Exemption.Name == "" || f.Exemption.Source == "" {
				t.Errorf("exempted finding for %s does not name the exception", f.Policy)
			}
		}
	}
	// Every policy must say something about every resource.
	for id := range known {
		for _, r := range resources {
			if !covered[id+"\x00"+r.Ref().Key()] {
				t.Errorf("no result for policy %s and resource %s", id, r.Ref())
			}
		}
	}

	// The same input gives the same output.
	second, err := eng.Evaluate(ctx, resources, first.Policies, ec)
	if err != nil {
		t.Fatalf("Evaluate (second time): %v", err)
	}
	if render(results) != render(second) {
		t.Error("evaluation is not deterministic")
	}

	// Evaluating a subset of policies must only report on that subset.
	subset := first.Policies[:1]
	some, err := eng.Evaluate(ctx, resources[:1], subset, ec)
	if err != nil {
		t.Fatalf("Evaluate (subset): %v", err)
	}
	for _, f := range some {
		if f.Policy != subset[0].ID {
			t.Errorf("subset evaluation reported on %s", f.Policy)
		}
	}
	if len(some) == 0 {
		t.Error("subset evaluation returned nothing")
	}
}

func ids(ps []policy.Policy) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.ID
	}
	return out
}

func render(fs []findings.Finding) string {
	lines := make([]string, len(fs))
	for i, f := range fs {
		lines[i] = strings.Join([]string{f.Policy, f.Rule, f.Resource.Key(), string(f.Status), f.Message, f.Field}, "|")
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func snapshot(rs []manifests.Resource) string {
	var b strings.Builder
	for _, r := range rs {
		b.WriteString(r.Ref().Key())
		b.WriteString(r.Namespace())
		b.WriteString("\n")
	}
	return b.String()
}
