package gatekeeper

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

func statuses(fs []findings.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, string(f.Status))
	}
	return strings.Join(out, ", ")
}

// labelsTemplate requires every label listed in parameters.labels.
const labelsTemplate = `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
  annotations:
    metadata.gatekeeper.sh/title: Required labels
    description: Resources must carry the listed labels.
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items: {type: string}
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels

        violation[{"msg": msg, "details": {"field": field, "remediation": fix, "label": label}}] {
          label := input.parameters.labels[_]
          not input.review.object.metadata.labels[label]
          field := sprintf("metadata.labels.%s", [label])
          fix := sprintf("add the label %s", [label])
          msg := sprintf("missing label %q", [label])
        }
`

func constraint(kind, name, spec string) string {
	return "---\napiVersion: constraints.gatekeeper.sh/v1beta1\nkind: " + kind + "\nmetadata:\n  name: " + name + "\n" + spec
}

const (
	podMatch = "spec:\n  match:\n    kinds:\n      - apiGroups: [\"\"]\n        kinds: [\"Pod\"]\n"
	labels   = "  parameters:\n    labels: [\"team\", \"owner\"]\n"

	pod = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: team-a, labels: {team: x}}\nspec: {containers: [{name: c, image: nginx}]}\n"
	svc = "apiVersion: v1\nkind: Service\nmetadata: {name: s, namespace: team-a}\n"
)

func TestConstraintIsThePolicy(t *testing.T) {
	ps, warnings := loadAll(t, map[string]string{"t.yaml": labelsTemplate + constraint("K8sRequiredLabels", "pods-need-labels", podMatch+labels)})
	if len(warnings) != 0 {
		t.Errorf("warnings = %v", warnings)
	}
	p := ps["pods-need-labels"]
	if p.ID != "gatekeeper/K8sRequiredLabels/pods-need-labels" || !p.Supported || p.Enforcement != policy.EnforceDeny ||
		p.Title != "Required labels" || p.Description == "" || strings.Join(p.Kinds, ",") != "Pod" || len(p.Rules) != 1 {
		t.Fatalf("policy = %+v", p)
	}
	if !strings.Contains(p.Raw, "kind: ConstraintTemplate") || !strings.Contains(p.Raw, "kind: K8sRequiredLabels") {
		t.Error("definition should hold the constraint and its template")
	}
	fs := eval(t, p, pod, evalctx.Context{})
	if statuses(fs) != "fail" || fs[0].Message != `missing label "owner"` || fs[0].Rule != "violation" {
		t.Fatalf("got %s %+v", statuses(fs), fs)
	}
	// "field" and "remediation" in the violation details become finding fields.
	if fs[0].Field != "metadata.labels.owner" || fs[0].Remediation == nil || fs[0].Remediation.Description != "add the label owner" || fs[0].Details["label"] != "owner" {
		t.Errorf("finding = %+v", fs[0])
	}
	bare := "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: team-a}\nspec: {containers: [{name: c, image: nginx}]}\n"
	if got := statuses(eval(t, p, bare, evalctx.Context{})); got != "fail, fail" {
		t.Errorf("every violation should be reported: %s", got)
	}
	good := "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: team-a, labels: {team: x, owner: y}}\nspec: {containers: [{name: c, image: nginx}]}\n"
	if got := statuses(eval(t, p, good+"---\n"+svc, evalctx.Context{})); got != "pass, not_applicable" {
		t.Errorf("got %s", got)
	}
}

func TestEnforcementActions(t *testing.T) {
	scoped := func(point string) string {
		return podMatch + labels + "  enforcementAction: scoped\n  scopedEnforcementActions:\n    - action: warn\n      enforcementPoints:\n        - name: " + point + "\n"
	}
	ps, _ := loadAll(t, map[string]string{"t.yaml": labelsTemplate +
		constraint("K8sRequiredLabels", "warn", podMatch+labels+"  enforcementAction: warn\n") +
		constraint("K8sRequiredLabels", "dryrun", podMatch+labels+"  enforcementAction: dryrun\n") +
		constraint("K8sRequiredLabels", "scoped", scoped("validation.gatekeeper.sh")) +
		constraint("K8sRequiredLabels", "audit-only", scoped("audit.gatekeeper.sh"))})
	for name, want := range map[string]string{"warn": policy.EnforceWarn, "dryrun": policy.EnforceAudit, "scoped": policy.EnforceWarn} {
		p := ps[name]
		fs := eval(t, p, pod, evalctx.Context{})
		if !p.Supported || p.Enforcement != want || statuses(fs) != "warning" || fs[0].Enforcement != want {
			t.Errorf("%s: enforcement %q, %s %+v", name, p.Enforcement, statuses(fs), fs)
		}
	}
	// A constraint with no action at admission does not apply there.
	fs := eval(t, ps["audit-only"], pod, evalctx.Context{})
	if statuses(fs) != "not_applicable" || !strings.Contains(fs[0].Message, "admission") {
		t.Errorf("audit-only: %s %+v", statuses(fs), fs)
	}
}

func TestMatchCriteriaAndNamespaceSelector(t *testing.T) {
	ps, _ := loadAll(t, map[string]string{"t.yaml": labelsTemplate +
		constraint("K8sRequiredLabels", "excluded", podMatch+"    excludedNamespaces: [\"team-*\"]\n"+labels) +
		constraint("K8sRequiredLabels", "prod", podMatch+"    namespaceSelector:\n      matchLabels: {env: prod}\n"+labels)})
	if got := statuses(eval(t, ps["excluded"], pod, evalctx.Context{})); got != "not_applicable" {
		t.Errorf("excluded namespace: %s", got)
	}
	p := ps["prod"]
	if strings.Join(p.RequiredContext, ",") != "namespace.labels" {
		t.Errorf("required context = %v", p.RequiredContext)
	}
	fs := eval(t, p, pod, evalctx.Context{})
	if statuses(fs) != "unknown" || strings.Join(fs[0].MissingContext, ",") != "namespace.labels" {
		t.Errorf("no labels: %s %+v", statuses(fs), fs)
	}
	if got := statuses(eval(t, p, pod, evalctx.Context{Namespace: &evalctx.Namespace{Name: "team-a"}})); got != "unknown" {
		t.Errorf("name only: %s", got)
	}
	prod := evalctx.Context{Namespace: &evalctx.Namespace{Name: "team-a", Labels: map[string]string{"env": "prod"}}}
	if got := statuses(eval(t, p, pod, prod)); got != "fail" {
		t.Errorf("prod: %s", got)
	}
	dev := evalctx.Context{Namespace: &evalctx.Namespace{Name: "team-a", Labels: map[string]string{"env": "dev"}}}
	if got := statuses(eval(t, p, pod, dev)); got != "not_applicable" {
		t.Errorf("dev: %s", got)
	}
	// A kind the constraint does not select is not_applicable, labels or not.
	if got := statuses(eval(t, p, svc, evalctx.Context{})); got != "not_applicable" {
		t.Errorf("service: %s", got)
	}
}

func TestConfigExcludesNamespaces(t *testing.T) {
	config := `---
apiVersion: config.gatekeeper.sh/v1alpha1
kind: Config
metadata: {name: config, namespace: gatekeeper-system}
spec:
  match:
    - excludedNamespaces: ["kube-*"]
      processes: ["webhook"]
    - excludedNamespaces: ["team-a"]
      processes: ["audit"]
`
	ps, _ := loadAll(t, map[string]string{"t.yaml": labelsTemplate + constraint("K8sRequiredLabels", "c", podMatch+labels) + config})
	system := "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: kube-system}\nspec: {containers: [{name: c, image: nginx}]}\n"
	fs := eval(t, ps["c"], system, evalctx.Context{})
	if statuses(fs) != "exempted" || fs[0].Exemption == nil || fs[0].Exemption.Source != exemptionSource || fs[0].Exemption.Name != "Config/gatekeeper-system/config" {
		t.Errorf("excluded: %s %+v", statuses(fs), fs)
	}
	// An exclusion for the audit process does not affect admission.
	if got := statuses(eval(t, ps["c"], pod, evalctx.Context{})); got != "fail" {
		t.Errorf("audit-only exclusion: %s", got)
	}
}

const uniqueHostTemplate = `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata: {name: k8suniqueservicename}
spec:
  crd:
    spec:
      names: {kind: K8sUniqueServiceName}
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8suniqueservicename

        violation[{"msg": msg}] {
          other := data.inventory.namespace[ns][_]["Service"][name]
          ns != input.review.object.metadata.namespace
          name == input.review.object.metadata.name
          msg := sprintf("service name %q is already used in namespace %q", [name, ns])
        }
`

func TestInventoryNeedsContextResources(t *testing.T) {
	match := "spec:\n  match:\n    kinds:\n      - apiGroups: [\"\"]\n        kinds: [\"Service\"]\n"
	ps, _ := loadAll(t, map[string]string{"t.yaml": uniqueHostTemplate + constraint("K8sUniqueServiceName", "unique", match)})
	p := ps["unique"]
	if !p.Supported || strings.Join(p.RequiredContext, ",") != "resources" {
		t.Fatalf("policy = %+v", p)
	}
	var ec evalctx.Context
	ec.Normalize()
	if missing := ec.Missing(p.RequiredContext, "team-a"); strings.Join(missing, ",") != "resources" {
		t.Errorf("missing = %v", missing)
	}
	other := func(name string) evalctx.Context {
		return evalctx.Context{Resources: []map[string]any{{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": name, "namespace": "team-b"}}}}
	}
	if got := statuses(eval(t, p, svc, other("s"))); got != "fail" {
		t.Errorf("clash: %s", got)
	}
	if got := statuses(eval(t, p, svc, other("different"))); got != "pass" {
		t.Errorf("no clash: %s", got)
	}
}

func TestExpansionTemplates(t *testing.T) {
	expansion := `---
apiVersion: expansion.gatekeeper.sh/v1beta1
kind: ExpansionTemplate
metadata: {name: expand-deployments}
spec:
  applyTo:
    - groups: ["apps"]
      kinds: ["Deployment"]
      versions: ["v1"]
  templateSource: "spec.template"
  generatedGVK: {kind: "Pod", group: "", version: "v1"}
`
	deploy := func(lbls string) string {
		return "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d, namespace: team-a}\nspec:\n  template:\n    metadata: {labels: " + lbls + "}\n    spec: {containers: [{name: c, image: nginx}]}\n"
	}
	ps, _ := loadAll(t, map[string]string{"t.yaml": labelsTemplate + constraint("K8sRequiredLabels", "c", podMatch+labels) + expansion})
	p := ps["c"]
	if strings.Join(p.Kinds, ",") != "Deployment,Pod" {
		t.Errorf("kinds = %v", p.Kinds)
	}
	fs := eval(t, p, deploy("{team: x}"), evalctx.Context{})
	if statuses(fs) != "fail" || !strings.Contains(fs[0].Message, "[Implied by expand-deployments]") {
		t.Errorf("got %s %+v", statuses(fs), fs)
	}
	if got := statuses(eval(t, p, deploy("{team: x, owner: y}"), evalctx.Context{})); got != "pass" {
		t.Errorf("compliant deployment: %s", got)
	}
	// Without the expansion template a Deployment is not selected at all.
	ps, _ = loadAll(t, map[string]string{"t.yaml": labelsTemplate + constraint("K8sRequiredLabels", "c", podMatch+labels)})
	if got := statuses(eval(t, ps["c"], deploy("{team: x}"), evalctx.Context{})); got != "not_applicable" {
		t.Errorf("no expansion: %s", got)
	}
}

func TestCELTemplate(t *testing.T) {
	tmpl := `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata: {name: k8snolatest}
spec:
  crd:
    spec:
      names: {kind: K8sNoLatest}
  targets:
    - target: admission.k8s.gatekeeper.sh
      code:
        - engine: K8sNativeValidation
          source:
            validations:
              - expression: "object.spec.containers.all(c, !c.image.endsWith(':latest'))"
                message: latest tag is not allowed
`
	ps, _ := loadAll(t, map[string]string{"t.yaml": tmpl + constraint("K8sNoLatest", "c", podMatch)})
	p := ps["c"]
	if !p.Supported {
		t.Fatalf("policy = %+v", p)
	}
	if got := statuses(eval(t, p, pod, evalctx.Context{})); got != "pass" {
		t.Errorf("tagless: %s", got)
	}
	latest := "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: team-a}\nspec: {containers: [{name: c, image: \"nginx:latest\"}]}\n"
	fs := eval(t, p, latest, evalctx.Context{})
	if statuses(fs) != "fail" || !strings.Contains(fs[0].Message, "latest tag is not allowed") {
		t.Errorf("latest: %s %+v", statuses(fs), fs)
	}
}

func TestBrokenAndUnsupported(t *testing.T) {
	badRego := strings.Replace(labelsTemplate, "not input.review.object.metadata.labels[label]", "not input.review.object.metadata.labels[label", 1)
	badRego = strings.ReplaceAll(strings.ReplaceAll(badRego, "k8srequiredlabels", "k8sbroken"), "K8sRequiredLabels", "K8sBroken")
	netTemplate := func(name, kind, body string) string {
		return "---\napiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\nmetadata: {name: " + name + "}\nspec:\n  crd:\n    spec:\n      names: {kind: " + kind + "}\n  targets:\n    - target: admission.k8s.gatekeeper.sh\n      rego: |\n        package " + name + "\n\n        violation[{\"msg\": msg}] {\n          " + body + "\n          msg := \"x\"\n        }\n"
	}
	ps, warnings := loadAll(t, map[string]string{
		"labels.yaml": labelsTemplate +
			constraint("K8sRequiredLabels", "bad-params", podMatch+"  parameters:\n    labels: \"not-a-list\"\n") +
			constraint("K8sMissing", "no-template", podMatch),
		"broken.yaml":   badRego + constraint("K8sBroken", "uses-broken", podMatch),
		"external.yaml": netTemplate("k8sexternal", "K8sExternal", `response := external_data({"provider": "p", "keys": ["k"]})`) + constraint("K8sExternal", "external", podMatch),
		"http.yaml":     netTemplate("k8shttp", "K8sHttp", `http.send({"method": "get", "url": "http://example.com"})`) + constraint("K8sHttp", "http", podMatch),
		"unused.yaml":   netTemplate("k8sunused", "K8sUnused", "true"),
		"other.yaml":    "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cm}\n---\napiVersion: mutations.gatekeeper.sh/v1\nkind: AssignMetadata\nmetadata: {name: m}\nspec: {}\n",
	})
	for _, name := range []string{"bad-params", "no-template", "uses-broken", "http"} {
		p := ps[name]
		if !p.LoadError || p.Supported || p.Problem == "" {
			t.Errorf("%s should be a load error: %+v", name, p)
		}
		if got := statuses(eval(t, p, pod, evalctx.Context{})); got != "error" {
			t.Errorf("%s: %s", name, got)
		}
	}
	p := ps["external"]
	if p.Supported || p.LoadError || !strings.Contains(p.Problem, "external_data") {
		t.Errorf("external should be unsupported: %+v", p)
	}
	if got := statuses(eval(t, p, pod+"---\n"+svc, evalctx.Context{})); got != "unknown, not_applicable" {
		t.Errorf("external: %s", got)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"k8sunused is not used by any constraint", "ConfigMap", "mutator AssignMetadata m"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings should mention %q:\n%s", want, joined)
		}
	}
}

func TestLimits(t *testing.T) {
	dir := source(t, map[string]string{"a.yaml": labelsTemplate, "b.yaml": labelsTemplate})
	if _, err := New().LoadSource(context.Background(), dir, policy.Limits{MaxPolicyFiles: 1}); err == nil {
		t.Error("file limit not enforced")
	}
	if _, err := New().LoadSource(context.Background(), dir, policy.Limits{MaxPolicyBytes: 10}); err == nil {
		t.Error("size limit not enforced")
	}
}
