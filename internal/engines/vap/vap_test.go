package vap

import (
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

func loadAll(t *testing.T, files map[string]string) (map[string]policy.Policy, []string) {
	t.Helper()
	res, err := New().LoadSource(context.Background(), source(t, files), policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]policy.Policy{}
	for _, p := range res.Policies {
		out[p.Name] = p
	}
	return out, res.Warnings
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

// statuses renders findings as "status rule" lines for compact assertions.
func statuses(fs []findings.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, strings.TrimSpace(string(f.Status)+" "+f.Rule))
	}
	return strings.Join(out, ", ")
}

// vap builds a policy that matches pods and config maps for all operations.
func vap(name, spec string) string {
	return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: ` + name + `
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["*"]
        resources: ["pods"]
` + spec
}

func binding(name, policyName, spec string) string {
	return `---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: ` + name + `
spec:
  policyName: ` + policyName + `
` + spec
}

const (
	deny = "  validationActions: [Deny]\n"
	pod  = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: team-a, labels: {app: x}}\nspec: {hostNetwork: true, hostPID: true, containers: [{name: c, image: nginx}]}\n"
	svc  = "apiVersion: v1\nkind: Service\nmetadata: {name: s, namespace: team-a}\n"

	hostChecks = `  validations:
    - expression: "!object.spec.?hostNetwork.orValue(false)"
      message: no host network
    - expression: "!object.spec.?hostPID.orValue(false)"
      messageExpression: "'no host PID for ' + object.metadata.name"
    - expression: "!object.spec.?hostIPC.orValue(false)"
      message: no host IPC
  auditAnnotations:
    - key: field.0
      valueExpression: "'spec.hostNetwork'"
    - key: remediation.1
      valueExpression: "'unset hostPID'"
`
)

func TestEveryFailingValidationIsReported(t *testing.T) {
	ps, _ := loadAll(t, map[string]string{"p.yaml": vap("host", hostChecks) + binding("host", "host", deny)})
	p := ps["host"]
	if !p.Supported || p.Enforcement != policy.EnforceDeny || len(p.Rules) != 3 || strings.Join(p.Kinds, ",") != "Pod" {
		t.Fatalf("policy = %+v", p)
	}
	fs := eval(t, p, pod, evalctx.Context{})
	if statuses(fs) != "fail validations[0], fail validations[1]" {
		t.Fatalf("got %s", statuses(fs))
	}
	if fs[0].Message != "no host network" || fs[0].Field != "spec.hostNetwork" {
		t.Errorf("first finding = %+v", fs[0])
	}
	if fs[1].Message != "no host PID for p" || fs[1].Remediation == nil || fs[1].Remediation.Description != "unset hostPID" {
		t.Errorf("second finding = %+v", fs[1])
	}
	good := "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: team-a}\nspec: {containers: [{name: c, image: nginx}]}\n"
	if got := statuses(eval(t, p, good, evalctx.Context{})); got != "pass" {
		t.Errorf("compliant pod: %s", got)
	}
	if got := statuses(eval(t, p, svc, evalctx.Context{})); got != "not_applicable" {
		t.Errorf("service: %s", got)
	}
}

func TestPolicyWithoutBindingIsUnknown(t *testing.T) {
	ps, warnings := loadAll(t, map[string]string{"p.yaml": vap("host", hostChecks) + binding("orphan", "elsewhere", deny)})
	p := ps["host"]
	if p.Supported || p.LoadError || !strings.Contains(p.Problem, "Binding") {
		t.Fatalf("policy = %+v", p)
	}
	if got := statuses(eval(t, p, pod+"---\n"+svc, evalctx.Context{})); got != "unknown, not_applicable" {
		t.Errorf("got %s", got)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "elsewhere") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestBindingActions(t *testing.T) {
	for action, want := range map[string]string{"Warn": policy.EnforceWarn, "Audit": policy.EnforceAudit} {
		ps, _ := loadAll(t, map[string]string{"p.yaml": vap("host", hostChecks) + binding("host", "host", "  validationActions: ["+action+"]\n")})
		p := ps["host"]
		if p.Enforcement != want {
			t.Errorf("%s: enforcement %q", action, p.Enforcement)
		}
		fs := eval(t, p, pod, evalctx.Context{})
		if statuses(fs) != "warning validations[0], warning validations[1]" || fs[0].Enforcement != want {
			t.Errorf("%s: %s %+v", action, statuses(fs), fs[0])
		}
	}
	// One binding that denies is enough to fail.
	ps, _ := loadAll(t, map[string]string{"p.yaml": vap("host", hostChecks) + binding("a", "host", "  validationActions: [Audit]\n") + binding("b", "host", deny)})
	fs := eval(t, ps["host"], pod, evalctx.Context{})
	fails := 0
	for _, f := range fs {
		if f.Status == findings.StatusFail {
			fails++
		}
	}
	if fails != 2 {
		t.Errorf("two bindings: %s", statuses(fs))
	}
}

func TestNamespaceSelectorNeedsLabels(t *testing.T) {
	sel := deny + "  matchResources:\n    namespaceSelector:\n      matchLabels: {env: prod}\n"
	ps, _ := loadAll(t, map[string]string{"p.yaml": vap("host", hostChecks) + binding("host", "host", sel)})
	p := ps["host"]
	if strings.Join(p.RequiredContext, ",") != "namespace.labels" {
		t.Errorf("required context = %v", p.RequiredContext)
	}
	fs := eval(t, p, pod, evalctx.Context{})
	if statuses(fs) != "unknown" || strings.Join(fs[0].MissingContext, ",") != "namespace.labels" {
		t.Errorf("no labels: %s %+v", statuses(fs), fs[0])
	}
	// A namespace given by name only does not state its labels.
	if got := statuses(eval(t, p, pod, evalctx.Context{Namespace: &evalctx.Namespace{Name: "team-a"}})); got != "unknown" {
		t.Errorf("name only: %s", got)
	}
	prod := evalctx.Context{Namespace: &evalctx.Namespace{Name: "team-a", Labels: map[string]string{"env": "prod"}}}
	if got := statuses(eval(t, p, pod, prod)); got != "fail validations[0], fail validations[1]" {
		t.Errorf("prod: %s", got)
	}
	dev := evalctx.Context{Namespace: &evalctx.Namespace{Name: "team-a", Labels: map[string]string{"env": "dev"}}}
	if got := statuses(eval(t, p, pod, dev)); got != "not_applicable" {
		t.Errorf("dev: %s", got)
	}
	// A kind the policy does not select is not_applicable, labels or not.
	if got := statuses(eval(t, p, svc, evalctx.Context{})); got != "not_applicable" {
		t.Errorf("service: %s", got)
	}
}

func TestNamespaceObjectNeedsLabels(t *testing.T) {
	spec := "  validations:\n    - expression: \"namespaceObject.metadata.labels['tier'] != 'restricted'\"\n      message: restricted namespace\n"
	ps, _ := loadAll(t, map[string]string{"p.yaml": vap("tier", spec) + binding("tier", "tier", deny)})
	p := ps["tier"]
	if got := statuses(eval(t, p, pod, evalctx.Context{})); got != "unknown" {
		t.Errorf("no namespace: %s", got)
	}
	ec := evalctx.Context{Namespace: &evalctx.Namespace{Name: "team-a", Labels: map[string]string{"tier": "restricted"}}}
	if got := statuses(eval(t, p, pod, ec)); got != "fail validations[0]" {
		t.Errorf("restricted: %s", got)
	}
}

func TestParameters(t *testing.T) {
	spec := `  paramKind: {apiVersion: v1, kind: ConfigMap}
  validations:
    - expression: "object.metadata.labels['app'] in params.data"
      message: app is not allowed
`
	ref := deny + "  paramRef: {name: allowed-apps, namespace: platform, parameterNotFoundAction: Allow}\n"
	cm := func(app string) string {
		return "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: allowed-apps, namespace: platform}\ndata: {" + app + ": \"true\"}\n"
	}
	ps, _ := loadAll(t, map[string]string{"p.yaml": vap("apps", spec) + binding("apps", "apps", ref)})
	fs := eval(t, ps["apps"], pod, evalctx.Context{})
	// Not found is unknown even with parameterNotFoundAction Allow.
	if statuses(fs) != "unknown" || strings.Join(fs[0].MissingContext, ",") != "resources" {
		t.Fatalf("missing param: %s %+v", statuses(fs), fs[0])
	}
	asContext := func(app string) evalctx.Context {
		return evalctx.Context{Resources: []map[string]any{{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": "allowed-apps", "namespace": "platform"},
			"data":     map[string]any{app: "true"},
		}}}
	}
	if got := statuses(eval(t, ps["apps"], pod, asContext("x"))); got != "pass" {
		t.Errorf("param in context: %s", got)
	}
	if got := statuses(eval(t, ps["apps"], pod, asContext("y"))); got != "fail validations[0]" {
		t.Errorf("param in context, not allowed: %s", got)
	}
	// A parameter object can also live in the policy source.
	ps, _ = loadAll(t, map[string]string{"p.yaml": vap("apps", spec) + binding("apps", "apps", ref), "params/cm.yaml": cm("x")})
	if got := statuses(eval(t, ps["apps"], pod, evalctx.Context{})); got != "pass" {
		t.Errorf("param in source: %s", got)
	}
	// The caller's object wins over the one in the source.
	if got := statuses(eval(t, ps["apps"], pod, asContext("y"))); got != "fail validations[0]" {
		t.Errorf("context overrides source: %s", got)
	}
}

func TestEvaluationErrorIsNeverAPass(t *testing.T) {
	spec := "  failurePolicy: Ignore\n  validations:\n    - expression: \"object.spec.doesNotExist.size() > 0\"\n      message: boom\n"
	ps, _ := loadAll(t, map[string]string{"p.yaml": vap("err", spec) + binding("err", "err", deny)})
	fs := eval(t, ps["err"], pod, evalctx.Context{})
	if statuses(fs) != "error validations[0]" || !strings.Contains(fs[0].Message, "CEL evaluation error") {
		t.Errorf("got %s %+v", statuses(fs), fs)
	}
}

func TestMatchConditionsAndOperations(t *testing.T) {
	spec := "  matchConditions:\n    - name: only-x\n      expression: \"object.metadata.name == 'other'\"\n" + hostChecks
	ps, _ := loadAll(t, map[string]string{"p.yaml": vap("cond", spec) + binding("cond", "cond", deny)})
	fs := eval(t, ps["cond"], pod, evalctx.Context{})
	if statuses(fs) != "not_applicable" || !strings.Contains(fs[0].Message, "match conditions") {
		t.Errorf("match conditions: %s %+v", statuses(fs), fs)
	}

	del := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata: {name: del}
spec:
  matchConstraints:
    resourceRules:
      - {apiGroups: [""], apiVersions: ["v1"], operations: ["DELETE"], resources: ["pods"]}
  validations:
    - expression: "oldObject.metadata.name != 'p'"
      message: p must not be deleted
`
	ps, _ = loadAll(t, map[string]string{"p.yaml": del + binding("del", "del", deny)})
	if got := statuses(eval(t, ps["del"], pod, evalctx.Context{})); got != "not_applicable" {
		t.Errorf("create: %s", got)
	}
	if got := statuses(eval(t, ps["del"], pod, evalctx.Context{Operation: "DELETE"})); got != "fail validations[0]" {
		t.Errorf("delete: %s", got)
	}
}

func TestUserInfo(t *testing.T) {
	spec := "  validations:\n    - expression: \"'admins' in request.userInfo.groups\"\n      message: only admins\n"
	ps, _ := loadAll(t, map[string]string{"p.yaml": vap("user", spec) + binding("user", "user", deny)})
	p := ps["user"]
	if strings.Join(p.RequiredContext, ",") != "user" {
		t.Errorf("required context = %v", p.RequiredContext)
	}
	admin := evalctx.Context{User: &evalctx.User{Username: "a", Groups: []string{"admins"}}}
	if got := statuses(eval(t, p, pod, admin)); got != "pass" {
		t.Errorf("admin: %s", got)
	}
	dev := evalctx.Context{User: &evalctx.User{Username: "d", Groups: []string{"devs"}}}
	if got := statuses(eval(t, p, pod, dev)); got != "fail validations[0]" {
		t.Errorf("dev: %s", got)
	}
}

func TestBrokenAndUnsupportedPolicies(t *testing.T) {
	ps, warnings := loadAll(t, map[string]string{
		"compile.yaml":  vap("compile", "  validations:\n    - expression: \"object.spec.(\"\n") + binding("compile", "compile", deny),
		"strict.yaml":   vap("strict", "  validatons: []\n") + binding("strict", "strict", deny),
		"authz.yaml":    vap("authz", "  validations:\n    - expression: \"authorizer.group('').resource('pods').check('get').allowed()\"\n") + binding("authz", "authz", deny),
		"nomatch.yaml":  "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata: {name: nomatch}\nspec:\n  validations:\n    - expression: \"true\"\n" + binding("nomatch", "nomatch", deny),
		"badbind.yaml":  vap("badbind", hostChecks) + binding("badbind", "badbind", "  validationActions: [Deny, Warn]\n"),
		"mutating.yaml": "apiVersion: admissionregistration.k8s.io/v1beta1\nkind: MutatingAdmissionPolicy\nmetadata: {name: mut}\nspec: {}\n",
		"webhook.yaml":  "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\nmetadata: {name: hook}\n",
		"dup.yaml":      vap("dup", hostChecks) + "---\n" + vap("dup", hostChecks) + binding("dup", "dup", deny),
	})
	for _, name := range []string{"compile", "strict", "nomatch", "dup"} {
		p := ps[name]
		if !p.LoadError || p.Supported || p.Problem == "" {
			t.Errorf("%s should be a load error: %+v", name, p)
		}
		if got := statuses(eval(t, p, pod, evalctx.Context{})); got != "error" {
			t.Errorf("%s: %s", name, got)
		}
	}
	for _, name := range []string{"authz", "mut", "badbind"} {
		p := ps[name]
		if p.Supported || p.LoadError || p.Problem == "" {
			t.Errorf("%s should be unsupported: %+v", name, p)
		}
		if got := statuses(eval(t, p, pod, evalctx.Context{})); got != "unknown" {
			t.Errorf("%s: %s", name, got)
		}
	}
	if b := ps["ValidatingAdmissionPolicyBinding/badbind"]; !b.LoadError {
		t.Errorf("invalid binding should be reported: %+v", b)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "ValidatingWebhookConfiguration") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestLimits(t *testing.T) {
	dir := source(t, map[string]string{"a.yaml": vap("a", hostChecks), "b.yaml": vap("b", hostChecks)})
	if _, err := New().LoadSource(context.Background(), dir, policy.Limits{MaxPolicyFiles: 1}); err == nil {
		t.Error("file limit not enforced")
	}
	if _, err := New().LoadSource(context.Background(), dir, policy.Limits{MaxPolicyBytes: 10}); err == nil {
		t.Error("size limit not enforced")
	}
}
