package evaluator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cosmosdevops/kube-policy-mcp/internal/config"
	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/packs"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// scripted is an engine whose behaviour each test sets.
type scripted struct {
	policies []policy.Policy
	eval     func(ctx context.Context, rs []manifests.Resource, ps []policy.Policy, ec evalctx.Context) ([]findings.Finding, error)
}

func (*scripted) Name() string                   { return "fake" }
func (*scripted) SupportedPolicyTypes() []string { return nil }
func (s *scripted) LoadSource(context.Context, string, policy.Limits) (policy.LoadResult, error) {
	return policy.LoadResult{Policies: s.policies}, nil
}
func (*scripted) ValidatePolicy(context.Context, policy.Policy) error { return nil }
func (s *scripted) Evaluate(ctx context.Context, rs []manifests.Resource, ps []policy.Policy, ec evalctx.Context) ([]findings.Finding, error) {
	return s.eval(ctx, rs, ps, ec)
}

func pol(name string, mod ...func(*policy.Policy)) policy.Policy {
	p := policy.Policy{ID: "fake/" + name, Name: name, Engine: "fake", Supported: true, Enforcement: policy.EnforceDeny}
	for _, m := range mod {
		m(&p)
	}
	return p
}

func setup(t *testing.T, eng *scripted, exemptions ...config.Exemption) *Evaluator {
	t.Helper()
	cfg := &config.Config{PolicyPacks: []config.Pack{{Name: "p", Sources: []config.Source{{Engine: "fake", Path: t.TempDir()}}, Exemptions: exemptions}}}
	return &Evaluator{Registry: packs.NewRegistry(cfg, eng), Timeout: 2 * time.Second}
}

func resources(t *testing.T, yaml string) []manifests.Resource {
	t.Helper()
	rs, err := manifests.Parse([]byte(yaml), "inline", manifests.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

const twoPods = "apiVersion: v1\nkind: Pod\nmetadata: {name: a, namespace: x}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: b, namespace: kube-system}\n"

// all returns the given status for every pair.
func all(st findings.Status) func(context.Context, []manifests.Resource, []policy.Policy, evalctx.Context) ([]findings.Finding, error) {
	return func(_ context.Context, rs []manifests.Resource, ps []policy.Policy, _ evalctx.Context) ([]findings.Finding, error) {
		var out []findings.Finding
		for _, p := range ps {
			for _, r := range rs {
				out = append(out, findings.Finding{Policy: p.ID, Resource: r.Ref(), Status: st, Message: "m"})
			}
		}
		return out, nil
	}
}

func TestVerdicts(t *testing.T) {
	cases := []struct {
		status                        findings.Status
		verdict                       findings.Status
		complete, compliant, reported bool
	}{
		{findings.StatusPass, findings.StatusPass, true, true, false},
		{findings.StatusNotApplicable, findings.StatusPass, true, true, false},
		{findings.StatusWarning, findings.StatusWarning, true, true, true},
		{findings.StatusExempted, findings.StatusPass, true, true, true},
		{findings.StatusFail, findings.StatusFail, true, false, true},
		{findings.StatusUnknown, findings.StatusUnknown, false, false, true},
		{findings.StatusError, findings.StatusUnknown, false, false, true},
	}
	for _, c := range cases {
		eng := &scripted{policies: []policy.Policy{pol("one")}, eval: all(c.status)}
		res, err := setup(t, eng).Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p"})
		if err != nil {
			t.Fatal(err)
		}
		r := res.Report
		if r.Status != c.verdict || r.Complete != c.complete || r.Compliant != c.compliant {
			t.Errorf("%s: verdict=%s complete=%t compliant=%t", c.status, r.Status, r.Complete, r.Compliant)
		}
		if (len(r.Findings) > 0) != c.reported {
			t.Errorf("%s: %d findings listed", c.status, len(r.Findings))
		}
		if len(res.All) != 2 {
			t.Errorf("%s: %d total findings", c.status, len(res.All))
		}
	}
}

func TestNotApplicableIsNeverCountedAsPass(t *testing.T) {
	eng := &scripted{policies: []policy.Policy{pol("one")}, eval: all(findings.StatusNotApplicable)}
	res, _ := setup(t, eng).Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p", IncludeAll: true})
	if res.Report.Summary.Passed != 0 || res.Report.Summary.NotApplicable != 2 {
		t.Errorf("summary = %+v", res.Report.Summary)
	}
	if res.Report.PolicyResults[0].Results[findings.StatusPass] != 0 {
		t.Error("policy result counted a pass")
	}
}

func TestEngineFailuresNeverBecomeCompliance(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	cases := map[string]func(context.Context, []manifests.Resource, []policy.Policy, evalctx.Context) ([]findings.Finding, error){
		"error": func(context.Context, []manifests.Resource, []policy.Policy, evalctx.Context) ([]findings.Finding, error) {
			return nil, errors.New("boom")
		},
		"panic": func(context.Context, []manifests.Resource, []policy.Policy, evalctx.Context) ([]findings.Finding, error) {
			panic("kaboom")
		},
		"no results": func(context.Context, []manifests.Resource, []policy.Policy, evalctx.Context) ([]findings.Finding, error) {
			return nil, nil
		},
		"partial results": func(_ context.Context, rs []manifests.Resource, ps []policy.Policy, _ evalctx.Context) ([]findings.Finding, error) {
			return []findings.Finding{{Policy: ps[0].ID, Resource: rs[0].Ref(), Status: findings.StatusPass}}, nil
		},
		"bogus status": func(_ context.Context, rs []manifests.Resource, ps []policy.Policy, _ evalctx.Context) ([]findings.Finding, error) {
			return []findings.Finding{{Policy: ps[0].ID, Resource: rs[0].Ref(), Status: "ok"}, {Policy: ps[0].ID, Resource: rs[1].Ref(), Status: ""}}, nil
		},
		"timeout": func(ctx context.Context, _ []manifests.Resource, _ []policy.Policy, _ evalctx.Context) ([]findings.Finding, error) {
			<-block
			return nil, nil
		},
	}
	for name, fn := range cases {
		eng := &scripted{policies: []policy.Policy{pol("one")}, eval: fn}
		ev := setup(t, eng)
		ev.Timeout = 100 * time.Millisecond
		res, err := ev.Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		r := res.Report
		if r.Compliant || r.Complete || r.Status == findings.StatusPass || r.Summary.Errors == 0 {
			t.Errorf("%s: verdict=%s complete=%t compliant=%t errors=%d", name, r.Status, r.Complete, r.Compliant, r.Summary.Errors)
		}
	}
}

func TestRequestErrors(t *testing.T) {
	eng := &scripted{policies: nil, eval: all(findings.StatusPass)}
	ev := setup(t, eng)
	if _, err := ev.Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p"}); err == nil || !strings.Contains(err.Error(), "no policies") {
		t.Errorf("empty pack must not pass: %v", err)
	}
	eng.policies = []policy.Policy{pol("one")}
	if _, err := ev.Evaluate(context.Background(), Request{Pack: "p"}); err == nil {
		t.Error("no resources must be an error")
	}
	if _, err := ev.Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p", PolicyIDs: []string{"fake/typo"}}); err == nil {
		t.Error("unknown policy id must be an error")
	}
	if _, err := ev.Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p", Context: evalctx.Context{Operation: "PATCH"}}); err == nil {
		t.Error("invalid operation must be an error")
	}
}

func TestPackExemptions(t *testing.T) {
	ex := []config.Exemption{
		{Name: "sys", Policies: []string{"fake/o*"}, Resource: config.ResourceSelector{Namespaces: []string{"kube-*"}}, Reason: "system"},
		{Name: "old", Policies: []string{"fake/one"}, Reason: "expired", Expires: "2020-01-01"},
	}
	eng := &scripted{policies: []policy.Policy{pol("one"), pol("two")}, eval: all(findings.StatusFail)}
	res, err := setup(t, eng, ex...).Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]findings.Status{}
	for _, f := range res.All {
		got[f.Policy+" "+f.Resource.Name] = f.Status
		if f.Status == findings.StatusExempted && (f.Exemption == nil || f.Exemption.Name != "sys" || f.Message == "") {
			t.Errorf("exemption details missing: %+v", f)
		}
	}
	want := map[string]findings.Status{"fake/one a": "fail", "fake/one b": "exempted", "fake/two a": "fail", "fake/two b": "fail"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
	if !strings.Contains(strings.Join(res.Report.Notes, "\n"), `"old"`) {
		t.Errorf("expired exemption not noted: %v", res.Report.Notes)
	}
	// An exemption must not hide an engine error.
	eng.eval = all(findings.StatusError)
	res, _ = setup(t, eng, ex...).Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p"})
	if res.Report.Summary.Exempted != 0 || res.Report.Complete {
		t.Error("exemption masked an error")
	}
}

func TestRequiredContext(t *testing.T) {
	needs := func(p *policy.Policy) { p.RequiredContext = []string{"namespace.labels", "user.groups"} }
	for _, st := range []findings.Status{findings.StatusPass, findings.StatusFail, findings.StatusNotApplicable} {
		eng := &scripted{policies: []policy.Policy{pol("ctx", needs)}, eval: all(st)}
		ev := setup(t, eng)
		res, _ := ev.Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p"})
		for _, f := range res.All {
			if f.Status != findings.StatusUnknown || len(f.MissingContext) != 2 || f.Remediation == nil {
				t.Errorf("%s without context: %+v", st, f)
			}
		}
		// Namespace given by name only: labels are still unknown.
		res, _ = ev.Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p",
			Context: evalctx.Context{Namespace: &evalctx.Namespace{Name: "x"}, User: &evalctx.User{Username: "u", Groups: []string{"g"}}}})
		if res.All[0].Status != findings.StatusUnknown {
			t.Errorf("%s: labels omitted but verdict was kept", st)
		}
		// Full context for namespace x only.
		res, _ = ev.Evaluate(context.Background(), Request{Resources: resources(t, twoPods), Pack: "p",
			Context: evalctx.Context{Namespace: &evalctx.Namespace{Name: "x", Labels: map[string]string{}}, User: &evalctx.User{Username: "u", Groups: []string{"g"}}}})
		if res.All[0].Status != st || res.All[1].Status != findings.StatusUnknown {
			t.Errorf("%s with context: %s / %s", st, res.All[0].Status, res.All[1].Status)
		}
	}
}

func TestNamespaceResourcesProvideContextAndDefaultNamespace(t *testing.T) {
	var seen evalctx.Context
	var seenNS string
	eng := &scripted{policies: []policy.Policy{pol("one")}}
	eng.eval = func(ctx context.Context, rs []manifests.Resource, ps []policy.Policy, ec evalctx.Context) ([]findings.Finding, error) {
		seen, seenNS = ec, rs[1].Namespace()
		return all(findings.StatusPass)(ctx, rs, ps, ec)
	}
	in := resources(t, "apiVersion: v1\nkind: Namespace\nmetadata: {name: team-a, labels: {environment: production}}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: p}\n")
	res, err := setup(t, eng).Evaluate(context.Background(), Request{Resources: in, Pack: "p", Context: evalctx.Context{Namespace: &evalctx.Namespace{Name: "team-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	if seenNS != "team-a" || in[1].Namespace() != "" {
		t.Errorf("default namespace: engine saw %q, input now %q", seenNS, in[1].Namespace())
	}
	if !strings.Contains(strings.Join(res.Report.Notes, "\n"), "as if deployed") {
		t.Error("namespace defaulting not noted")
	}
	// The explicit context wins over the Namespace object for the same name.
	if ns, _ := seen.NamespaceFor("team-a"); ns.Labels != nil {
		t.Errorf("context namespace was overwritten: %+v", ns)
	}
	if seen.Operation != "CREATE" {
		t.Errorf("operation default = %q", seen.Operation)
	}
}

func TestRemediationAndExplain(t *testing.T) {
	withMeta := func(p *policy.Policy) {
		p.Description, p.Remediation, p.Docs = "Pods need a team label.", "Add the team label.", []string{"https://example.com/doc"}
		p.Rules = []policy.Rule{{ID: "deny", Description: "team label must be set"}}
	}
	eng := &scripted{policies: []policy.Policy{pol("meta", withMeta), pol("bare")}}
	eng.eval = func(_ context.Context, rs []manifests.Resource, ps []policy.Policy, _ evalctx.Context) ([]findings.Finding, error) {
		var out []findings.Finding
		for _, p := range ps {
			out = append(out, findings.Finding{Policy: p.ID, Resource: rs[0].Ref(), Status: findings.StatusFail, Rule: "deny/x", Field: "metadata.name", Message: "no team label"})
		}
		return out, nil
	}
	res, _ := setup(t, eng).Evaluate(context.Background(), Request{Resources: resources(t, twoPods)[:1], Pack: "p"})
	bare, meta := res.Report.Findings[0], res.Report.Findings[1]
	if meta.Remediation.Source != "policy-metadata" || meta.Remediation.Description != "Add the team label." || len(meta.Remediation.Docs) != 1 {
		t.Errorf("meta remediation = %+v", meta.Remediation)
	}
	if bare.Remediation.Source != "derived-from-message" || !strings.Contains(bare.Remediation.Description, "no team label") {
		t.Errorf("bare remediation = %+v", bare.Remediation)
	}
	ex, err := res.Explain(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Rule == nil || ex.Expected != "team label must be set" || ex.Actual == nil || !ex.Actual.Found || ex.Actual.Value != `"a"` {
		t.Errorf("explanation = %+v actual=%+v", ex, ex.Actual)
	}
	if _, err := res.Explain("f-nope-001"); err == nil {
		t.Error("unknown finding id must fail")
	}
}

func TestSecretValuesAreRedacted(t *testing.T) {
	eng := &scripted{policies: []policy.Policy{pol("leaky")}}
	eng.eval = func(_ context.Context, rs []manifests.Resource, ps []policy.Policy, _ evalctx.Context) ([]findings.Finding, error) {
		pw := rs[0].Object["stringData"].(map[string]any)["password"].(string)
		return []findings.Finding{{Policy: ps[0].ID, Resource: rs[0].Ref(), Status: findings.StatusFail, Field: "stringData.password",
			Message: "weak password: " + pw, Details: map[string]any{"value": pw, "list": []any{pw}}}}, nil
	}
	in := resources(t, "apiVersion: v1\nkind: Secret\nmetadata: {name: db, namespace: x}\nstringData: {password: hunter2-hunter2}\n")
	res, _ := setup(t, eng).Evaluate(context.Background(), Request{Resources: in, Pack: "p"})
	f := res.Report.Findings[0]
	ex, _ := res.Explain(f.ID)
	dump := f.Message + f.Remediation.Description + ex.Summary + ex.Actual.Value + f.Details["value"].(string) + f.Details["list"].([]any)[0].(string)
	if strings.Contains(dump, "hunter2") {
		t.Errorf("secret leaked: %s", dump)
	}
}
