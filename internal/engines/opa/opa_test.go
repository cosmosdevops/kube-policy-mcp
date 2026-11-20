package opa

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

func source(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func load(t *testing.T, path string) map[string]policy.Policy {
	t.Helper()
	res, err := New().LoadSource(context.Background(), path, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]policy.Policy{}
	for _, p := range res.Policies {
		out[p.Name] = p
	}
	return out
}

func eval(t *testing.T, p policy.Policy, yaml string, ec evalctx.Context) []findings.Finding {
	t.Helper()
	rs, err := manifests.Parse([]byte(yaml), "inline", manifests.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ec.Normalize(); err != nil {
		t.Fatal(err)
	}
	fs, err := New().Evaluate(context.Background(), rs, []policy.Policy{p}, ec)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

const pod = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: team-a, labels: {app: x}}\nspec: {containers: [{name: c, image: nginx}]}\n"
const svc = "apiVersion: v1\nkind: Service\nmetadata: {name: s, namespace: team-a}\n"

func TestMetadataRulesAndResultShapes(t *testing.T) {
	ps := load(t, source(t, map[string]string{
		"lib/helpers.rego": "package lib.helpers\n\nname(obj) := obj.metadata.name\n",
		"labels.rego": `# METADATA
# title: Team label
# description: Pods need a team label.
# related_resources:
#   - ref: https://example.com/labels
# custom:
#   severity: high
#   kinds: [Pod]
#   remediation: Add the team label.
#   version: 2
package k8s.labels

import data.lib.helpers

# METADATA
# title: team label must be set
deny contains result if {
	not input.metadata.labels.team
	result := {"msg": sprintf("%s has no team label", [helpers.name(input)]), "field": "metadata.labels.team", "id": "team", "extra": 1}
}

warn contains "consider adding a cost-centre label" if not input.metadata.labels["cost-centre"]
`,
		"labels_test.rego": "package k8s.labels_test\n\ntest_x if true\n",
	}))
	if len(ps) != 1 {
		t.Fatalf("helper or test package listed as a policy: %v", ps)
	}
	p := ps["k8s.labels"]
	if p.ID != "opa/k8s.labels" || p.Title != "Team label" || p.Severity != "high" || p.Version != "2" || p.Remediation != "Add the team label." ||
		p.Enforcement != policy.EnforceDeny || len(p.Docs) != 1 || strings.Join(p.Kinds, ",") != "Pod" || !p.Supported {
		t.Errorf("metadata = %+v", p)
	}
	if len(p.Rules) != 2 || p.Rules[0].ID != "deny" || p.Rules[0].Description != "team label must be set" || p.Rules[1].Enforcement != policy.EnforceWarn {
		t.Errorf("rules = %+v", p.Rules)
	}
	if !strings.Contains(p.Raw, "deny contains result") {
		t.Error("raw definition missing")
	}

	fs := eval(t, p, pod+"---\n"+svc, evalctx.Context{})
	if len(fs) != 3 {
		t.Fatalf("findings = %+v", fs)
	}
	deny, warn, na := fs[0], fs[1], fs[2]
	if deny.Status != findings.StatusFail || deny.Rule != "deny/team" || deny.Field != "metadata.labels.team" || deny.Message != "p has no team label" || deny.Details["extra"] == nil || deny.Severity != "high" {
		t.Errorf("deny = %+v", deny)
	}
	if warn.Status != findings.StatusWarning || warn.Rule != "warn" || warn.Enforcement != policy.EnforceWarn {
		t.Errorf("warn = %+v", warn)
	}
	if na.Status != findings.StatusNotApplicable || na.Resource.Kind != "Service" {
		t.Errorf("not applicable = %+v", na)
	}
	ok := eval(t, p, strings.Replace(pod, "app: x", "team: a, cost-centre: c1", 1), evalctx.Context{})
	if len(ok) != 1 || ok[0].Status != findings.StatusPass {
		t.Errorf("compliant pod = %+v", ok)
	}
}

func TestContextDataAndUnknown(t *testing.T) {
	ps := load(t, source(t, map[string]string{
		"data.yaml":       "allowed_teams: [payments]\n",
		"teams/data.json": `{"owners": {"payments": "jane"}}`,
		"ctx.rego": `package k8s.ctx

ns := data.kubepolicy.namespaces[input.metadata.namespace]

applies if data.kubepolicy.context.operation == "CREATE"

unknown contains {"msg": "namespace labels are needed", "missingContext": ["namespace.labels"]} if not ns

deny contains "team not allowed" if {
	not ns.labels.team in data.allowed_teams
}

deny contains "no owner" if not data.teams.owners[ns.labels.team]

deny contains "needs a config map" if {
	count([r | some r in data.kubepolicy.resources; r.kind == "ConfigMap"]) == 0
}

deny contains "developers only" if not "developers" in data.kubepolicy.context.user.groups

deny contains "wrong env" if data.kubepolicy.context.variables.environment != "production"

deny contains "wrong data" if data.kubepolicy.data.tier != "gold"
`,
	}))
	p := ps["k8s.ctx"]
	fs := eval(t, p, pod, evalctx.Context{})
	var unknown bool
	for _, f := range fs {
		if f.Status == findings.StatusUnknown && len(f.MissingContext) == 1 {
			unknown = true
		}
		if f.Status == findings.StatusPass {
			t.Error("pass reported next to unknown")
		}
	}
	if !unknown {
		t.Errorf("missing namespace not reported as unknown: %+v", fs)
	}
	full := evalctx.Context{
		Namespace: &evalctx.Namespace{Name: "team-a", Labels: map[string]string{"team": "payments"}},
		User:      &evalctx.User{Username: "dev", Groups: []string{"developers"}},
		Variables: map[string]any{"environment": "production"},
		Data:      map[string]any{"tier": "gold"},
		Resources: []map[string]any{{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "cm"}}},
	}
	fs = eval(t, p, pod, full)
	if len(fs) != 1 || fs[0].Status != findings.StatusPass {
		t.Errorf("with full context: %+v", fs)
	}
	full.Operation = "delete"
	fs = eval(t, p, pod, full)
	if len(fs) != 1 || fs[0].Status != findings.StatusNotApplicable {
		t.Errorf("applies rule ignored: %+v", fs)
	}
}

func TestBrokenPoliciesProduceErrorsNotPasses(t *testing.T) {
	cases := map[string]string{
		"syntax error":     "package k8s.bad\n\ndeny contains msg if {\n",
		"network builtin":  "package k8s.bad\n\ndeny contains msg if {\n\tresp := http.send({\"method\": \"GET\", \"url\": \"http://example.com\"})\n\tmsg := resp.status\n}\n",
		"runtime builtin":  "package k8s.bad\n\ndeny contains msg if {\n\tmsg := opa.runtime().env.HOME\n}\n",
		"unsafe variable":  "package k8s.bad\n\ndeny contains msg if input.x == y\n",
		"builtin failure":  "package k8s.bad\n\ndeny contains msg if {\n\tmsg := sprintf(\"%d\", [to_number(input.metadata.name)])\n}\n",
		"conflicting rule": "package k8s.bad\n\nlimit := 1\n\nlimit := 2\n\ndeny contains \"x\" if limit > 0\n",
	}
	for name, src := range cases {
		ps := load(t, source(t, map[string]string{"bad.rego": src, "good.rego": "package k8s.good\n\ndeny contains \"never\" if false\n"}))
		if len(ps) == 0 {
			t.Fatalf("%s: broken policy vanished from the listing", name)
		}
		for pname, p := range ps {
			if pname == "k8s.good" && (name == "builtin failure" || name == "conflicting rule" || name == "syntax error") {
				continue // these do not break the rest of the source
			}
			fs := eval(t, p, pod, evalctx.Context{})
			if len(fs) != 1 || fs[0].Status != findings.StatusError {
				t.Errorf("%s: policy %s gave %+v", name, pname, fs)
			}
		}
	}
}

func TestRegoV0Fallback(t *testing.T) {
	ps := load(t, source(t, map[string]string{"old.rego": "package k8s.old\n\ndeny[msg] {\n\tinput.kind == \"Pod\"\n\tmsg := \"v0 syntax works\"\n}\n\nviolation[{\"msg\": msg}] {\n\tmsg := \"violation rule\"\n}\n"}))
	fs := eval(t, ps["k8s.old"], pod, evalctx.Context{})
	if len(fs) != 2 || fs[0].Message != "v0 syntax works" || fs[1].Rule != "violation" || fs[1].Status != findings.StatusFail {
		t.Errorf("v0 policy: %+v", fs)
	}
}

func TestReservedDataRootAndLimits(t *testing.T) {
	dir := source(t, map[string]string{"data.json": `{"kubepolicy": {"context": {}}}`, "a.rego": "package a\n\ndeny contains \"x\" if true\n"})
	if _, err := New().LoadSource(context.Background(), dir, policy.Limits{}); err == nil {
		t.Error("policy data may not overwrite the context root")
	}
	dir = source(t, map[string]string{"a.rego": "package a\n\ndeny contains \"x\" if true\n", "b.rego": "package b\n\ndeny contains \"x\" if true\n"})
	if _, err := New().LoadSource(context.Background(), dir, policy.Limits{MaxPolicyFiles: 1}); err == nil {
		t.Error("file count limit not enforced")
	}
	if _, err := New().LoadSource(context.Background(), dir, policy.Limits{MaxPolicyBytes: 5}); err == nil {
		t.Error("file size limit not enforced")
	}
}

func TestTarballBundle(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range map[string]string{
		"/policies/b.rego":    "package bundle.b\n\ndeny contains msg if {\n\tinput.kind == data.settings.blocked\n\tmsg := \"blocked kind\"\n}\n",
		"/settings/data.json": `{"blocked": "Pod"}`,
		"/.manifest":          `{"revision": "1"}`,
	} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg})
		tw.Write([]byte(content))
	}
	tw.Close()
	gz.Close()
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	os.WriteFile(path, buf.Bytes(), 0o600)
	fs := eval(t, load(t, path)["bundle.b"], pod, evalctx.Context{})
	if len(fs) != 1 || fs[0].Status != findings.StatusFail || fs[0].Message != "blocked kind" {
		t.Errorf("bundle policy: %+v", fs)
	}
}

func TestCancelledContextIsAnError(t *testing.T) {
	ps := load(t, source(t, map[string]string{"slow.rego": "package k8s.slow\n\ndeny contains \"x\" if {\n\tsome i in numbers.range(1, 2000000)\n\ti < 0\n}\n"}))
	rs, _ := manifests.Parse([]byte(pod), "inline", manifests.Limits{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fs, err := New().Evaluate(ctx, rs, []policy.Policy{ps["k8s.slow"]}, evalctx.Context{})
	if err == nil && (len(fs) != 1 || fs[0].Status != findings.StatusError) {
		t.Errorf("cancelled evaluation gave %+v", fs)
	}
}
