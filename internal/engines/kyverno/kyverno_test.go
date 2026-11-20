package kyverno

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

func vpol(name, extraMeta, specBody string) string {
	return fmt.Sprintf(`apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: %s
%s
spec:
%s
`, name, extraMeta, specBody)
}

const matchPods = `  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
`

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

func load(t *testing.T, files map[string]string) (map[string]policy.Policy, []string) {
	t.Helper()
	res, err := New().LoadSource(context.Background(), source(t, files), policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]policy.Policy{}
	for _, p := range res.Policies {
		out[p.ID] = p
	}
	return out, res.Warnings
}

func eval(t *testing.T, ps []policy.Policy, yaml string, ec evalctx.Context) []findings.Finding {
	t.Helper()
	rs, err := manifests.Parse([]byte(yaml), "inline", manifests.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ec.Normalize(); err != nil {
		t.Fatal(err)
	}
	fs, err := New().Evaluate(context.Background(), rs, ps, ec)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func deployment(name, ns, podSpec string) string {
	return fmt.Sprintf("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: %s, namespace: %s, labels: {team: pay}}\nspec:\n  template:\n    spec:\n      %s\n      containers: [{name: c, image: 'nginx:1.27'}]\n", name, ns, podSpec)
}

const hostNetPolicy = matchPods + `  validations:
    - expression: "!object.spec.?hostNetwork.orValue(false)"
      message: host network is not allowed
    - expression: "!object.spec.?hostPID.orValue(false)"
      message: host PID is not allowed
`

func TestMetadataAutogenAndVerdicts(t *testing.T) {
	ps, _ := load(t, map[string]string{"p.yaml": vpol("no-host-net", `  annotations:
    policies.kyverno.io/title: No host network
    policies.kyverno.io/description: Pods must not use the host network.
    policies.kyverno.io/severity: high
    kubepolicy.dev/remediation: Remove hostNetwork.
    kubepolicy.dev/docs: "https://example.com/a, https://example.com/b"`, "  validationActions: [Deny]\n"+hostNetPolicy)})
	p := ps["kyverno/no-host-net"]
	if !p.Supported || p.Title != "No host network" || p.Severity != "high" || p.Enforcement != policy.EnforceDeny || p.Remediation != "Remove hostNetwork." || len(p.Docs) != 2 {
		t.Fatalf("metadata = %+v", p)
	}
	// Autogen extends the Pod policy to pod controllers.
	for _, k := range []string{"Pod", "Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job"} {
		if !p.AppliesToKind(k) {
			t.Errorf("kind %s missing from %v", k, p.Kinds)
		}
	}
	if p.AppliesToKind("Service") {
		t.Error("policy should not list Service")
	}
	if len(p.Rules) != 2 || p.Rules[1].ID != "validations[1]" || p.Rules[1].Message != "host PID is not allowed" || p.Rules[0].Expression == "" {
		t.Errorf("rules = %+v", p.Rules)
	}

	in := deployment("bad", "team-a", "hostPID: true") + "---\n" + deployment("good", "team-a", "") +
		"---\napiVersion: v1\nkind: Pod\nmetadata: {name: pod, namespace: team-a}\nspec: {hostNetwork: true, containers: [{name: c, image: nginx}]}\n" +
		"---\napiVersion: v1\nkind: Service\nmetadata: {name: svc, namespace: team-a}\n"
	fs := eval(t, []policy.Policy{p}, in, evalctx.Context{})
	if len(fs) != 4 {
		t.Fatalf("findings = %+v", fs)
	}
	if fs[0].Status != findings.StatusFail || fs[0].Rule != "validations[1]" || fs[0].Message != "host PID is not allowed" || fs[0].Severity != "high" {
		t.Errorf("bad deployment = %+v", fs[0])
	}
	if fs[1].Status != findings.StatusPass {
		t.Errorf("good deployment = %+v", fs[1])
	}
	if fs[2].Status != findings.StatusFail || fs[2].Rule != "validations[0]" {
		t.Errorf("pod = %+v", fs[2])
	}
	if fs[3].Status != findings.StatusNotApplicable {
		t.Errorf("service must be not_applicable, got %+v", fs[3])
	}
	// DELETE is not in the policy's operations, so nothing applies.
	fs = eval(t, []policy.Policy{p}, deployment("bad", "team-a", "hostPID: true"), evalctx.Context{Operation: "DELETE"})
	if fs[0].Status != findings.StatusNotApplicable {
		t.Errorf("DELETE = %+v", fs[0])
	}
}

func TestWarnAndAuditActionsAreWarnings(t *testing.T) {
	ps, _ := load(t, map[string]string{
		"warn.yaml":  vpol("warn-only", "", "  validationActions: [Warn]\n"+hostNetPolicy),
		"audit.yaml": vpol("audit-only", "", "  validationActions: [Audit]\n"+hostNetPolicy),
	})
	for id, want := range map[string]string{"kyverno/warn-only": policy.EnforceWarn, "kyverno/audit-only": policy.EnforceAudit} {
		p := ps[id]
		if p.Enforcement != want {
			t.Errorf("%s enforcement = %s", id, p.Enforcement)
		}
		fs := eval(t, []policy.Policy{p}, deployment("bad", "team-a", "hostNetwork: true"), evalctx.Context{})
		if fs[0].Status != findings.StatusWarning {
			t.Errorf("%s = %+v", id, fs[0])
		}
	}
}

func TestPolicyExceptions(t *testing.T) {
	exception := `apiVersion: policies.kyverno.io/v1
kind: PolicyException
metadata: {name: allow-agent, namespace: monitoring}
spec:
  policyRefs: [{name: no-host-net, kind: ValidatingPolicy}]
  matchConditions:
    - name: agent
      expression: "object.metadata.name == 'agent'"
`
	ps, _ := load(t, map[string]string{
		"p.yaml":      vpol("no-host-net", "", "  validationActions: [Deny]\n"+hostNetPolicy),
		"other.yaml":  vpol("other", "", "  validationActions: [Deny]\n"+hostNetPolicy),
		"ex/a.yaml":   exception,
		"values.yaml": "foo: bar\n",
	})
	p, other := ps["kyverno/no-host-net"], ps["kyverno/other"]
	if len(p.Exceptions) != 1 || p.Exceptions[0].Name != "monitoring/allow-agent" || len(other.Exceptions) != 0 {
		t.Errorf("exception metadata: %+v / %+v", p.Exceptions, other.Exceptions)
	}
	in := deployment("agent", "monitoring", "hostNetwork: true") + "---\n" + deployment("web", "monitoring", "hostNetwork: true")
	fs := eval(t, []policy.Policy{p, other}, in, evalctx.Context{})
	got := map[string]findings.Finding{}
	for _, f := range fs {
		got[f.Policy+" "+f.Resource.Name] = f
	}
	if f := got["kyverno/no-host-net agent"]; f.Status != findings.StatusExempted || f.Exemption == nil || f.Exemption.Name != "monitoring/allow-agent" {
		t.Errorf("exception not honoured: %+v", f)
	}
	// The exception covers one resource and one policy only.
	for _, k := range []string{"kyverno/no-host-net web", "kyverno/other agent", "kyverno/other web"} {
		if got[k].Status != findings.StatusFail {
			t.Errorf("%s = %s, want fail", k, got[k].Status)
		}
	}
}

func TestMissingContextIsUnknown(t *testing.T) {
	ps, _ := load(t, map[string]string{
		"sel.yaml": vpol("prod-only", "", `  validationActions: [Deny]
  matchConstraints:
    namespaceSelector: {matchLabels: {environment: production}}
    resourceRules:
      - {apiGroups: ["apps"], apiVersions: ["v1"], operations: ["CREATE"], resources: ["deployments"]}
  validations:
    - expression: "object.spec.?replicas.orValue(1) >= 2"
      message: need two replicas
`),
		"nsobj.yaml": vpol("ns-object", "", `  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - {apiGroups: ["apps"], apiVersions: ["v1"], operations: ["CREATE"], resources: ["deployments"]}
  validations:
    - expression: "namespaceObject.metadata.?labels.?team.orValue('') == object.metadata.labels.team"
      message: team label must match the namespace
`),
		"lookup.yaml": vpol("lookup", "", `  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - {apiGroups: ["apps"], apiVersions: ["v1"], operations: ["CREATE"], resources: ["deployments"]}
  validations:
    - expression: "object.metadata.labels.team in resource.Get('v1', 'configmaps', 'platform', 'teams').data"
      message: team is not registered
`),
		"user.yaml": vpol("user", "", `  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - {apiGroups: ["apps"], apiVersions: ["v1"], operations: ["CREATE"], resources: ["deployments"]}
  validations:
    - expression: "'deployers' in request.userInfo.groups"
      message: only deployers may create deployments
`),
	})
	sel, nsobj, lookup, user := ps["kyverno/prod-only"], ps["kyverno/ns-object"], ps["kyverno/lookup"], ps["kyverno/user"]
	if strings.Join(sel.RequiredContext, ",") != "namespace.labels" || strings.Join(nsobj.RequiredContext, ",") != "namespace" || strings.Join(user.RequiredContext, ",") != "user" {
		t.Errorf("required context: %v %v %v", sel.RequiredContext, nsobj.RequiredContext, user.RequiredContext)
	}
	in := deployment("web", "shop", "")
	all := []policy.Policy{sel, nsobj, lookup}

	// No context at all: nothing may pass or be silently skipped.
	for _, f := range eval(t, all, in, evalctx.Context{}) {
		if f.Status != findings.StatusUnknown || len(f.MissingContext) == 0 {
			t.Errorf("no context: %s = %+v", f.Policy, f)
		}
	}
	// Namespace named but labels omitted: still unknown.
	for _, f := range eval(t, []policy.Policy{sel, nsobj}, in, evalctx.Context{Namespace: &evalctx.Namespace{Name: "shop"}}) {
		if f.Status != findings.StatusUnknown {
			t.Errorf("labels omitted: %s = %s", f.Policy, f.Status)
		}
	}
	teams := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "teams", "namespace": "platform"}, "data": map[string]any{"pay": "x"}}
	prod := evalctx.Context{Namespace: &evalctx.Namespace{Name: "shop", Labels: map[string]string{"environment": "production", "team": "pay"}}, Resources: []map[string]any{teams}}
	want := map[string]findings.Status{"kyverno/prod-only": findings.StatusFail, "kyverno/ns-object": findings.StatusPass, "kyverno/lookup": findings.StatusPass}
	for _, f := range eval(t, all, in, prod) {
		if f.Status != want[f.Policy] {
			t.Errorf("production context: %s = %s (%s), want %s", f.Policy, f.Status, f.Message, want[f.Policy])
		}
	}
	dev := evalctx.Context{Namespace: &evalctx.Namespace{Name: "shop", Labels: map[string]string{"environment": "dev", "team": "other"}}, Resources: []map[string]any{teams}}
	want = map[string]findings.Status{"kyverno/prod-only": findings.StatusNotApplicable, "kyverno/ns-object": findings.StatusFail, "kyverno/lookup": findings.StatusPass}
	for _, f := range eval(t, all, in, dev) {
		if f.Status != want[f.Policy] {
			t.Errorf("dev context: %s = %s, want %s", f.Policy, f.Status, want[f.Policy])
		}
	}
	// A Namespace object submitted with the manifests is not looked at by the
	// adapter itself; the evaluator turns it into context. User info is passed through.
	fs := eval(t, []policy.Policy{user}, in, evalctx.Context{User: &evalctx.User{Username: "u", Groups: []string{"deployers"}}})
	if fs[0].Status != findings.StatusPass {
		t.Errorf("user groups not passed to the engine: %+v", fs[0])
	}
	fs = eval(t, []policy.Policy{user}, in, evalctx.Context{User: &evalctx.User{Username: "u", Groups: []string{"viewers"}}})
	if fs[0].Status != findings.StatusFail {
		t.Errorf("user groups check: %+v", fs[0])
	}
}

func TestUnsupportedAndBrokenPolicies(t *testing.T) {
	ps, warnings := load(t, map[string]string{
		"legacy.yaml": "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata: {name: legacy}\nspec:\n  rules:\n    - name: r\n      match: {any: [{resources: {kinds: [Pod]}}]}\n      validate: {message: m, pattern: {spec: {hostNetwork: false}}}\n",
		"mutate.yaml": "apiVersion: policies.kyverno.io/v1\nkind: MutatingPolicy\nmetadata: {name: mut}\nspec: {}\n",
		"vap.yaml":    "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata: {name: vap}\nspec: {}\n",
		"http.yaml":   vpol("calls-http", "", "  validationActions: [Deny]\n"+matchPods+"  validations:\n    - expression: \"http.Get('https://example.com/allow').allowed\"\n      message: remote says no\n"),
		"image.yaml":  vpol("reads-registry", "", "  validationActions: [Deny]\n"+matchPods+"  validations:\n    - expression: \"object.spec.containers.all(c, image.GetMetadata(c.image).config.user != '')\"\n      message: image must set a user\n"),
		"badcel.yaml": vpol("bad-cel", "", "  validationActions: [Deny]\n"+matchPods+"  validations:\n    - expression: \"object.spec.nope(\"\n      message: broken\n"),
		"typo.yaml":   vpol("typo", "", "  validationActions: [Deny]\n"+matchPods+"  validationz: []\n"),
		"cm.yaml":     "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: not-a-policy}\n",
	})
	if len(warnings) != 1 || !strings.Contains(warnings[0], "ConfigMap") {
		t.Errorf("warnings = %v", warnings)
	}
	in := deployment("web", "team-a", "") + "---\napiVersion: v1\nkind: Service\nmetadata: {name: svc, namespace: team-a}\n"
	wantStatus := map[string]findings.Status{
		"kyverno/ClusterPolicy/legacy":          findings.StatusUnknown,
		"kyverno/MutatingPolicy/mut":            findings.StatusUnknown,
		"kyverno/ValidatingAdmissionPolicy/vap": findings.StatusUnknown,
		"kyverno/calls-http":                    findings.StatusUnknown,
		"kyverno/reads-registry":                findings.StatusUnknown,
		"kyverno/bad-cel":                       findings.StatusError,
		"kyverno/typo":                          findings.StatusError,
	}
	if len(ps) != len(wantStatus) {
		t.Fatalf("policies = %v", keys(ps))
	}
	for id, want := range wantStatus {
		p, ok := ps[id]
		if !ok {
			t.Errorf("%s missing; have %v", id, keys(ps))
			continue
		}
		if p.Supported || p.Problem == "" {
			t.Errorf("%s should be marked unsupported with a reason: %+v", id, p)
		}
		if err := New().ValidatePolicy(context.Background(), p); err == nil {
			t.Errorf("%s validated", id)
		}
		fs := eval(t, []policy.Policy{p}, in, evalctx.Context{})
		if fs[0].Status != want {
			t.Errorf("%s on Deployment = %s (%s), want %s", id, fs[0].Status, fs[0].Message, want)
		}
		for _, f := range fs {
			if f.Status == findings.StatusPass {
				t.Errorf("%s produced a pass", id)
			}
		}
	}
	if !strings.Contains(ps["kyverno/ClusterPolicy/legacy"].Problem, "Migrate") {
		t.Errorf("legacy hint = %q", ps["kyverno/ClusterPolicy/legacy"].Problem)
	}
	// An http policy is unknown for kinds it may match and not applicable elsewhere.
	fs := eval(t, []policy.Policy{ps["kyverno/calls-http"]}, in, evalctx.Context{})
	if fs[1].Status != findings.StatusNotApplicable {
		t.Errorf("http policy on Service = %s", fs[1].Status)
	}
}

func TestNamespacedPolicyScope(t *testing.T) {
	ps, _ := load(t, map[string]string{"n.yaml": strings.Replace(strings.Replace(vpol("local", "  namespace: team-a", "  validationActions: [Deny]\n"+hostNetPolicy), "kind: ValidatingPolicy", "kind: NamespacedValidatingPolicy", 1), "", "", 0)})
	p, ok := ps["kyverno/team-a/local"]
	if !ok || !p.Supported {
		t.Fatalf("policies = %v %+v", keys(ps), p)
	}
	in := deployment("a", "team-a", "hostNetwork: true") + "---\n" + deployment("b", "team-b", "hostNetwork: true")
	fs := eval(t, []policy.Policy{p}, in, evalctx.Context{})
	if fs[0].Status != findings.StatusFail || fs[1].Status != findings.StatusNotApplicable {
		t.Errorf("scope: %s / %s (%s)", fs[0].Status, fs[1].Status, fs[0].Message)
	}
}

func TestDuplicatePolicyNamesAreAnError(t *testing.T) {
	ps, _ := load(t, map[string]string{
		"a.yaml": vpol("same", "", "  validationActions: [Deny]\n"+hostNetPolicy),
		"b.yaml": vpol("same", "", "  validationActions: [Audit]\n"+hostNetPolicy),
	})
	p := ps["kyverno/same"]
	if len(ps) != 1 || !p.LoadError {
		t.Fatalf("duplicate not flagged: %+v", ps)
	}
	if fs := eval(t, []policy.Policy{p}, deployment("a", "x", ""), evalctx.Context{}); fs[0].Status != findings.StatusError {
		t.Errorf("duplicate policy = %s", fs[0].Status)
	}
}

func keys(m map[string]policy.Policy) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestHTTPDetection(t *testing.T) {
	blocked := []string{
		"http.Get('https://x').ok",
		"x && http . Get('u').ok",
		"variables.h.Get('u')\nhttp", // alias through a variable
		"http\n.Client('ca').Post('u', {})",
		"object.metadata.name in http.Get(\"http://x\").names",
	}
	for _, e := range blocked {
		if !usesHTTP(e) {
			t.Errorf("not blocked: %q", e)
		}
	}
	allowed := []string{
		"object.spec.http.port == 80",
		"object.metadata.annotations['url'].startsWith('http://')",
		"object.spec.rules.all(r, has(r.http))",
		"object.spec.httpRoute == 'x' && object.spec.https",
		"url == \"https://example.com\"",
	}
	for _, e := range allowed {
		if usesHTTP(e) {
			t.Errorf("wrongly blocked: %q", e)
		}
	}
}
