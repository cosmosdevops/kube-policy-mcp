// Package tests holds end-to-end tests. They build the real binary and talk
// to it the way an MCP client or a CI pipeline would. No cluster is used.
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	binary   string
	repoRoot string
)

func TestMain(m *testing.M) {
	wd, _ := os.Getwd()
	repoRoot = filepath.Dir(wd)
	dir, err := os.MkdirTemp("", "kube-policy-mcp-e2e")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "kube-policy-mcp")
	build := exec.Command("go", "build", "-o", binary, "./cmd/kube-policy-mcp")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func example(parts ...string) string {
	return filepath.Join(append([]string{repoRoot, "examples"}, parts...)...)
}

// connect starts the server over stdio, exactly as an MCP client does.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	cmd := exec.Command(binary, "serve", "--config", example("kube-policy-mcp.yaml"))
	// No kubeconfig and no cluster environment: the server must work offline.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "KUBECONFIG=/nonexistent"}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-test", Version: "0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

type finding struct {
	ID       string `json:"id"`
	Engine   string `json:"engine"`
	Policy   string `json:"policy"`
	Rule     string `json:"rule"`
	Status   string `json:"status"`
	Field    string `json:"field"`
	Message  string `json:"message"`
	Resource struct {
		Kind, Name, Namespace string
	} `json:"resource"`
	MissingContext []string `json:"missingContext"`
	Remediation    *struct {
		Description string `json:"description"`
		Source      string `json:"source"`
	} `json:"remediation"`
	Exemption *struct {
		Name   string `json:"name"`
		Source string `json:"source"`
	} `json:"exemption"`
}

type report struct {
	EvaluationID string `json:"evaluationId"`
	Status       string `json:"status"`
	Complete     bool   `json:"complete"`
	Compliant    bool   `json:"compliant"`
	PolicyPack   string `json:"policyPack"`
	Summary      struct {
		ResourcesEvaluated, PoliciesEvaluated, Violations, Warnings, Unknown, Errors, Exempted, Passed, NotApplicable int
	} `json:"summary"`
	PolicyResults []struct {
		Policy  string         `json:"policy"`
		Engine  string         `json:"engine"`
		Results map[string]int `json:"results"`
	} `json:"policyResults"`
	Findings []finding `json:"findings"`
	Files    []struct {
		Path      string `json:"path"`
		Resources []struct {
			Status   string    `json:"status"`
			Findings []finding `json:"findings"`
		} `json:"resources"`
	} `json:"files"`
	SkippedFiles []struct{ Path, Reason string } `json:"skippedFiles"`
}

// call invokes a tool and decodes its structured result into out.
func call(t *testing.T, s *mcp.ClientSession, tool string, args map[string]any, out any) (isError bool, text string) {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", tool, err)
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	if res.IsError {
		return true, text
	}
	if out != nil {
		raw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) == "null" {
			raw = []byte(text)
		}
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s: cannot decode result: %v\n%s", tool, err, raw)
		}
	}
	return false, text
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestAgentWorkflow follows the acceptance workflow: discover packs and
// policies, submit a Deployment, read the violations, fix the manifest and
// evaluate again until it passes.
func TestAgentWorkflow(t *testing.T) {
	s := connect(t)

	tools, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tool := range tools.Tools {
		have[tool.Name] = true
		if tool.Description == "" || tool.InputSchema == nil {
			t.Errorf("tool %s lacks a description or schema", tool.Name)
		}
	}
	for _, name := range []string{"list_policy_packs", "list_policies", "get_policy", "evaluate_manifests", "evaluate_directory", "explain_violation"} {
		if !have[name] {
			t.Errorf("tool %s is missing", name)
		}
	}

	// 2. Discover packs.
	var packs struct {
		DefaultPolicyPack string `json:"defaultPolicyPack"`
		PolicyPacks       []struct {
			Name    string   `json:"name"`
			Extends []string `json:"extends"`
		} `json:"policyPacks"`
		Engines []string `json:"engines"`
	}
	call(t, s, "list_policy_packs", nil, &packs)
	if packs.DefaultPolicyPack != "platform-baseline" || len(packs.PolicyPacks) != 2 || strings.Join(packs.Engines, ",") != "kyverno,opa" {
		t.Fatalf("packs = %+v", packs)
	}

	// 3. Inspect the policies that apply to a Deployment.
	var list struct {
		Count    int `json:"count"`
		Policies []struct {
			ID, Engine, Description, Severity string
			Kinds                             []string
			Supported                         bool
		} `json:"policies"`
	}
	call(t, s, "list_policies", map[string]any{"kind": "Deployment"}, &list)
	engines := map[string]int{}
	for _, p := range list.Policies {
		engines[p.Engine]++
		if p.Description == "" || !p.Supported {
			t.Errorf("policy %s: description or support missing", p.ID)
		}
	}
	if list.Count != 11 || engines["opa"] != 6 || engines["kyverno"] != 5 {
		t.Fatalf("Deployment policies: count=%d engines=%v", list.Count, engines)
	}
	call(t, s, "list_policies", map[string]any{"kind": "ConfigMap"}, &list)
	if list.Count != 1 || list.Policies[0].ID != "opa/kubernetes.restricted_namespaces" {
		t.Errorf("ConfigMap policies = %+v", list.Policies)
	}
	call(t, s, "list_policies", map[string]any{"engine": "kyverno", "policyPack": "production"}, &list)
	if list.Count != 7 {
		t.Errorf("production kyverno policies = %d", list.Count)
	}

	var pol struct {
		Policy struct {
			ID, Title, Remediation, Enforcement string
			Rules                               []struct{ ID, Expression, Message string }
			Exceptions                          []struct{ Name string }
		} `json:"policy"`
		Definition string `json:"definition"`
	}
	call(t, s, "get_policy", map[string]any{"policy": "kyverno/disallow-host-namespaces", "includeDefinition": true}, &pol)
	if len(pol.Policy.Rules) != 3 || pol.Policy.Rules[0].Expression == "" || len(pol.Policy.Exceptions) != 1 ||
		!strings.Contains(pol.Definition, "kind: ValidatingPolicy") || pol.Policy.Remediation == "" {
		t.Errorf("get_policy = %+v", pol)
	}
	if isErr, _ := call(t, s, "get_policy", map[string]any{"policy": "kyverno/nope"}, nil); !isErr {
		t.Error("unknown policy must be a tool error")
	}

	// 4-6. Submit a non-compliant Deployment; both engines report violations.
	var bad report
	call(t, s, "evaluate_manifests", map[string]any{"manifests": read(t, example("manifests", "noncompliant", "web.yaml"))}, &bad)
	if bad.Status != "fail" || bad.Compliant || !bad.Complete || bad.Summary.Violations == 0 || bad.Summary.PoliciesEvaluated != 11 {
		t.Fatalf("non-compliant report = %+v", bad)
	}
	byEngine := map[string]int{}
	byPolicy := map[string]finding{}
	for _, f := range bad.Findings {
		if f.Status == "fail" {
			byEngine[f.Engine]++
			byPolicy[f.Policy] = f
		}
		// 7. Every violation carries enough to act on.
		if f.ID == "" || f.Message == "" || f.Remediation == nil || f.Remediation.Description == "" {
			t.Errorf("finding lacks detail: %+v", f)
		}
	}
	if byEngine["opa"] == 0 || byEngine["kyverno"] == 0 {
		t.Fatalf("want violations from both engines, got %v", byEngine)
	}
	for _, id := range []string{
		"opa/kubernetes.required_owner_labels", "opa/kubernetes.resource_limits", "opa/kubernetes.approved_registries",
		"opa/kubernetes.health_probes", "opa/kubernetes.restricted_namespaces",
		"kyverno/disallow-privileged-containers", "kyverno/disallow-host-namespaces", "kyverno/require-run-as-non-root",
		"kyverno/restrict-hostpath-volumes", "kyverno/require-memory-limits",
	} {
		if _, ok := byPolicy[id]; !ok {
			t.Errorf("expected a violation of %s", id)
		}
	}

	// 7. Explain one finding of each engine.
	var ex struct {
		Summary  string `json:"summary"`
		Expected string `json:"expected"`
		Actual   *struct {
			Field string `json:"field"`
			Found bool   `json:"found"`
			Value string `json:"value"`
		} `json:"actual"`
		Policy struct{ ID, Description string } `json:"policy"`
		Rule   *struct{ ID, Expression string } `json:"rule"`
	}
	call(t, s, "explain_violation", map[string]any{"findingId": byPolicy["opa/kubernetes.approved_registries"].ID}, &ex)
	if ex.Actual == nil || !ex.Actual.Found || ex.Actual.Value != `"nginx:latest"` || ex.Expected == "" || ex.Policy.Description == "" {
		t.Errorf("rego explanation = %+v", ex)
	}
	ex.Actual, ex.Rule = nil, nil
	call(t, s, "explain_violation", map[string]any{"findingId": byPolicy["kyverno/disallow-host-namespaces"].ID}, &ex)
	if ex.Rule == nil || !strings.Contains(ex.Expected, "hostNetwork") || !strings.Contains(ex.Summary, "Deployment/default/web") {
		t.Errorf("kyverno explanation = %+v", ex)
	}
	if isErr, _ := call(t, s, "explain_violation", map[string]any{"findingId": "f-00000000-001"}, nil); !isErr {
		t.Error("explaining an unknown finding must be a tool error")
	}

	// 8-9. The corrected manifest passes.
	var good report
	call(t, s, "evaluate_manifests", map[string]any{"manifests": read(t, example("manifests", "compliant", "web.yaml"))}, &good)
	if good.Status != "pass" || !good.Compliant || !good.Complete || len(good.Findings) != 0 || good.Summary.ResourcesEvaluated != 2 {
		t.Fatalf("corrected manifest report = %+v", good)
	}
	// Non-applicable policies are counted apart from passes.
	if good.Summary.NotApplicable == 0 || good.Summary.Passed+good.Summary.NotApplicable != 22 {
		t.Errorf("summary = %+v", good.Summary)
	}
	for _, pr := range good.PolicyResults {
		if pr.Policy == "kyverno/disallow-host-namespaces" && (pr.Results["pass"] != 1 || pr.Results["not_applicable"] != 1) {
			t.Errorf("Service must be not_applicable for a pod policy: %v", pr.Results)
		}
	}
}

func TestFilesDirectoryAndWorkspaceLimits(t *testing.T) {
	s := connect(t)

	var r report
	call(t, s, "evaluate_manifests", map[string]any{"files": []string{"compliant/web.yaml", "multi/app.yaml"}, "options": map[string]any{"includeAllResults": true}}, &r)
	if r.Summary.ResourcesEvaluated != 5 || r.Status != "fail" {
		t.Errorf("files report: %+v", r.Summary)
	}
	statuses := map[string]bool{}
	for _, f := range r.Findings {
		statuses[f.Status] = true
	}
	if !statuses["pass"] || !statuses["not_applicable"] {
		t.Errorf("includeAllResults did not list pass and not_applicable: %v", statuses)
	}

	for _, p := range []string{"../kube-policy-mcp.yaml", "/etc/hostname", example("policies", "rego", "data.yaml")} {
		isErr, text := call(t, s, "evaluate_manifests", map[string]any{"files": []string{p}}, nil)
		if !isErr || !strings.Contains(text, "workspace") {
			t.Errorf("path %s was not refused: %s", p, text)
		}
	}
	if isErr, _ := call(t, s, "evaluate_directory", map[string]any{"directory": ".."}, nil); !isErr {
		t.Error("directory outside the workspace was not refused")
	}
	if isErr, _ := call(t, s, "evaluate_manifests", map[string]any{}, nil); !isErr {
		t.Error("empty request must be a tool error")
	}
	if isErr, _ := call(t, s, "evaluate_manifests", map[string]any{"manifests": "replicas: 2"}, nil); !isErr {
		t.Error("non-manifest input must be a tool error")
	}
	if isErr, _ := call(t, s, "evaluate_manifests", map[string]any{"manifests": "apiVersion: v1\nkind: Pod\nmetadata: {name: p}", "policyPack": "nope"}, nil); !isErr {
		t.Error("unknown pack must be a tool error")
	}

	var dir report
	call(t, s, "evaluate_directory", map[string]any{"directory": "."}, &dir)
	if dir.Summary.ResourcesEvaluated != 8 || len(dir.Files) != 5 || len(dir.SkippedFiles) != 1 || dir.Status != "fail" {
		t.Fatalf("directory report: files=%d skipped=%d summary=%+v", len(dir.Files), len(dir.SkippedFiles), dir.Summary)
	}
	for _, f := range dir.Files {
		switch f.Path {
		case "compliant/web.yaml":
			if len(f.Resources) != 2 || f.Resources[0].Status != "pass" || len(f.Resources[0].Findings) != 0 {
				t.Errorf("compliant file group = %+v", f)
			}
		case "noncompliant/web.yaml":
			if f.Resources[0].Status != "fail" || len(f.Resources[0].Findings) == 0 {
				t.Errorf("noncompliant file group = %+v", f)
			}
		case "exemptions/node-exporter.yaml":
			if f.Resources[0].Status != "exempted" {
				t.Errorf("exemption file group status = %s", f.Resources[0].Status)
			}
		}
	}
}

func TestExemptionsAreHonoured(t *testing.T) {
	s := connect(t)
	var r report
	call(t, s, "evaluate_manifests", map[string]any{"files": []string{"exemptions/node-exporter.yaml"}}, &r)
	if !r.Compliant || r.Summary.Exempted != 2 || r.Summary.Violations != 0 {
		t.Fatalf("report = %+v", r.Summary)
	}
	sources := map[string]string{}
	for _, f := range r.Findings {
		if f.Status != "exempted" || f.Exemption == nil {
			t.Errorf("unexpected finding %+v", f)
			continue
		}
		sources[f.Policy] = f.Exemption.Source
	}
	if sources["kyverno/disallow-host-namespaces"] != "kyverno-policy-exception" || sources["opa/kubernetes.approved_registries"] != "pack-exemption" {
		t.Errorf("exemption sources = %v", sources)
	}
	// The same DaemonSet under another name is not covered.
	other := strings.ReplaceAll(read(t, example("manifests", "exemptions", "node-exporter.yaml")), "name: node-exporter\n  namespace", "name: other-agent\n  namespace")
	call(t, s, "evaluate_manifests", map[string]any{"manifests": other}, &r)
	if r.Status != "fail" || r.Summary.Exempted != 0 || r.Summary.Violations < 2 {
		t.Errorf("exemption applied too broadly: %+v", r.Summary)
	}
}

func TestMissingContextIsSurfaced(t *testing.T) {
	s := connect(t)
	manifest := read(t, example("manifests", "production", "checkout.yaml"))

	var r report
	call(t, s, "evaluate_manifests", map[string]any{"manifests": manifest, "policyPack": "production"}, &r)
	if r.Status != "unknown" || r.Complete || r.Compliant || r.Summary.Unknown != 3 || r.Summary.Violations != 0 {
		t.Fatalf("without context: status=%s complete=%t summary=%+v", r.Status, r.Complete, r.Summary)
	}
	for _, f := range r.Findings {
		if f.Status != "unknown" || len(f.MissingContext) == 0 || f.Remediation == nil {
			t.Errorf("unknown finding lacks detail: %+v", f)
		}
	}

	ctx := map[string]any{
		"kubernetesVersion": "1.35",
		"namespace":         map[string]any{"name": "checkout", "labels": map[string]any{"environment": "production"}},
		"operation":         "CREATE",
		"user":              map[string]any{"username": "developer@example.com", "groups": []string{"developers"}},
		"resources": []any{map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": "registered-teams", "namespace": "platform-system"},
			"data":     map[string]any{"checkout": "true"},
		}},
	}
	call(t, s, "evaluate_manifests", map[string]any{"manifests": manifest, "policyPack": "production", "context": ctx}, &r)
	if r.Status != "pass" || !r.Compliant || r.Summary.Passed != 14 {
		t.Fatalf("with context: status=%s summary=%+v findings=%+v", r.Status, r.Summary, r.Findings)
	}

	// The same context makes real violations visible: one replica, an unregistered team.
	broken := strings.Replace(strings.Replace(manifest, "replicas: 3", "replicas: 1", 1), "team: checkout", "team: ghosts", 1)
	call(t, s, "evaluate_manifests", map[string]any{"manifests": broken, "policyPack": "production", "context": ctx}, &r)
	failed := map[string]bool{}
	for _, f := range r.Findings {
		if f.Status == "fail" {
			failed[f.Policy] = true
		}
	}
	if !failed["opa/production.min_replicas"] || !failed["kyverno/require-registered-team"] || len(failed) != 2 {
		t.Errorf("context-dependent violations = %v", failed)
	}

	// A non-production namespace: the production-only policies do not apply.
	ctx["namespace"] = map[string]any{"name": "checkout", "labels": map[string]any{"environment": "dev"}}
	call(t, s, "evaluate_manifests", map[string]any{"manifests": broken, "policyPack": "production", "context": ctx, "policies": []string{"opa/production.min_replicas", "kyverno/disallow-latest-tag-in-production"}}, &r)
	if r.Summary.NotApplicable != 2 || r.Summary.Passed != 0 || r.Summary.PoliciesEvaluated != 2 {
		t.Errorf("dev namespace: %+v", r.Summary)
	}
}

func TestSecretsAreNotEchoed(t *testing.T) {
	s := connect(t)
	secret := "apiVersion: v1\nkind: Secret\nmetadata: {name: db, namespace: default}\nstringData: {password: s3cr3t-value-123}\n"
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "evaluate_manifests", Arguments: map[string]any{"manifests": secret, "options": map[string]any{"includeAllResults": true}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	if bytes.Contains(raw, []byte("s3cr3t-value-123")) {
		t.Error("secret value appears in the tool result")
	}
	if !bytes.Contains(raw, []byte("restricted namespace")) {
		t.Errorf("expected the restricted namespace violation: %s", raw)
	}
}

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "KUBE_POLICY_MCP_CONFIG=" + example("kube-policy-mcp.yaml")}
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func TestCLI(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"compliant", []string{"evaluate", "--file", example("manifests", "compliant", "web.yaml"), "--policy-pack", "platform-baseline"}, 0, "Verdict:     PASS"},
		{"violations", []string{"evaluate", "-f", example("manifests", "noncompliant", "web.yaml")}, 1, "Verdict:     FAIL"},
		{"incomplete", []string{"evaluate", "-f", example("manifests", "production", "checkout.yaml"), "--policy-pack", "production"}, 2, "Verdict:     UNKNOWN"},
		{"with context", []string{"evaluate", "-f", example("manifests", "production", "checkout.yaml"), "--policy-pack", "production", "--context-file", example("manifests", "production", "context.yaml")}, 0, "compliant: true"},
		{"directory", []string{"evaluate", "--dir", example("manifests")}, 1, "skipped"},
		{"bad pack", []string{"evaluate", "-f", example("manifests", "compliant", "web.yaml"), "--policy-pack", "nope"}, 3, "unknown policy pack"},
		{"no input", []string{"evaluate"}, 3, "--file"},
		{"packs", []string{"packs"}, 0, "platform-baseline (default)"},
		{"policies", []string{"policies", "--engine", "opa"}, 0, "opa/kubernetes.resource_limits"},
		{"policy", []string{"policy", "opa/kubernetes.health_probes", "--definition"}, 0, "package kubernetes.health_probes"},
	}
	for _, c := range cases {
		code, out := runCLI(t, c.args...)
		if code != c.code || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d (want %d), output lacks %q:\n%s", c.name, code, c.code, c.want, out)
		}
	}
	code, out := runCLI(t, "evaluate", "-f", example("manifests", "noncompliant", "web.yaml"), "-o", "json", "--explain")
	var payload struct {
		Report       report `json:"report"`
		Explanations []any  `json:"explanations"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil || code != 1 || payload.Report.Status != "fail" || len(payload.Explanations) != len(payload.Report.Findings) {
		t.Errorf("json output: code=%d err=%v", code, err)
	}
}

// buildVariant builds the binary with build tags and returns its path.
func buildVariant(t *testing.T, name, tags string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-tags", tags, "-o", out, "./cmd/kube-policy-mcp")
	cmd.Dir = repoRoot
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build -tags %q: %v\n%s", tags, err, b)
	}
	return out
}

// writeConfig writes a config whose single pack uses the given sources.
func writeConfig(t *testing.T, extra string, sources ...[2]string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(extra)
	b.WriteString("policyPacks:\n  - name: only\n    sources:\n")
	for _, s := range sources {
		fmt.Fprintf(&b, "      - engine: %s\n        path: %s\n", s[0], example("policies", s[1]))
	}
	path := filepath.Join(t.TempDir(), "kube-policy-mcp.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func run(t *testing.T, bin, config string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "KUBE_POLICY_MCP_CONFIG=" + config}
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

// TestSingleEngineBuilds checks that each engine can be left out at build
// time, that the remaining engine still works on its own, and that a pack
// needing the missing engine is refused rather than partly evaluated.
func TestSingleEngineBuilds(t *testing.T) {
	bad := example("manifests", "noncompliant", "web.yaml")
	good := example("manifests", "compliant", "web.yaml")
	variants := []struct {
		engine, other, tags, source, otherSource, upstream string
		violations                                         string
	}{
		{"opa", "kyverno", "no_kyverno", "rego", "kyverno", "github.com/open-policy-agent/opa", "opa/kubernetes.resource_limits"},
		{"kyverno", "opa", "no_opa", "kyverno", "rego", "github.com/kyverno/kyverno", "kyverno/disallow-host-namespaces"},
	}
	for _, v := range variants {
		t.Run(v.engine+" only", func(t *testing.T) {
			bin := buildVariant(t, "kube-policy-mcp-"+v.engine, v.tags)

			// The other engine's code is really gone from the binary.
			mods, err := exec.Command("go", "version", "-m", bin).CombinedOutput()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(mods), v.upstream) {
				t.Errorf("%s is missing from its own build", v.upstream)
			}
			for _, o := range variants {
				if o.engine != v.engine && strings.Contains(string(mods), "\t"+o.upstream+"\t") {
					t.Errorf("%s is still linked into the %s-only build", o.upstream, v.engine)
				}
			}

			code, out := run(t, bin, "", "engines")
			if code != 0 || !strings.HasPrefix(out, v.engine+":") || strings.Contains(out, "\n"+v.other+":") {
				t.Errorf("engines output:\n%s", out)
			}

			// A pack that only needs this engine works end to end.
			own := writeConfig(t, "", [2]string{v.engine, v.source})
			code, out = run(t, bin, own, "evaluate", "-f", bad)
			if code != 1 || !strings.Contains(out, v.violations) || strings.Contains(out, v.other+"/") {
				t.Errorf("own pack, bad manifest: exit %d\n%s", code, out)
			}
			code, out = run(t, bin, own, "evaluate", "-f", good)
			if code != 0 || !strings.Contains(out, "Verdict:     PASS") {
				t.Errorf("own pack, good manifest: exit %d\n%s", code, out)
			}

			// A pack that needs the missing engine is refused as a whole.
			both := writeConfig(t, "", [2]string{v.engine, v.source}, [2]string{v.other, v.otherSource})
			code, out = run(t, bin, both, "evaluate", "-f", good)
			if code != 3 || !strings.Contains(out, `engine "`+v.other+`", which is not part of this build`) {
				t.Errorf("mixed pack must be refused: exit %d\n%s", code, out)
			}
			code, out = run(t, bin, both, "packs")
			if code != 0 || !strings.Contains(out, "NOT USABLE") {
				t.Errorf("packs must flag the unusable pack: exit %d\n%s", code, out)
			}

			// Asking for an absent engine in the config is an error;
			// turning an absent engine off is harmless.
			code, out = run(t, bin, writeConfig(t, "engines:\n  "+v.other+":\n    enabled: true\n", [2]string{v.engine, v.source}), "packs")
			if code != 3 || !strings.Contains(out, "not part of this build") {
				t.Errorf("enabling an absent engine: exit %d\n%s", code, out)
			}
			code, out = run(t, bin, writeConfig(t, "engines:\n  "+v.other+":\n    enabled: false\n", [2]string{v.engine, v.source}), "evaluate", "-f", good)
			if code != 0 {
				t.Errorf("disabling an absent engine: exit %d\n%s", code, out)
			}

			// The MCP server works with one engine and says which it has.
			cmd := exec.Command(bin, "serve", "--config", own)
			client := mcp.NewClient(&mcp.Implementation{Name: "e2e-test", Version: "0"}, nil)
			session, err := client.Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			var packs struct {
				Engines       []string `json:"engines"`
				EngineDetails []struct {
					Name, Title, UpstreamVersion string
					Enabled                      bool
					Limitations                  []string
				} `json:"engineDetails"`
			}
			call(t, session, "list_policy_packs", nil, &packs)
			if len(packs.Engines) != 1 || packs.Engines[0] != v.engine || len(packs.EngineDetails) != 1 ||
				!packs.EngineDetails[0].Enabled || packs.EngineDetails[0].UpstreamVersion == "" || len(packs.EngineDetails[0].Limitations) == 0 {
				t.Errorf("list_policy_packs = %+v", packs)
			}
			if instr := session.InitializeResult().Instructions; !strings.Contains(instr, packs.EngineDetails[0].Title) {
				t.Errorf("server instructions do not name the engine: %s", instr)
			}
			var r report
			call(t, session, "evaluate_manifests", map[string]any{"manifests": read(t, bad)}, &r)
			if r.Status != "fail" || len(r.Findings) == 0 {
				t.Fatalf("report = %+v", r.Summary)
			}
			for _, f := range r.Findings {
				if f.Engine != v.engine {
					t.Errorf("finding from engine %s in a %s-only build", f.Engine, v.engine)
				}
			}
		})
	}

	t.Run("no engines", func(t *testing.T) {
		bin := buildVariant(t, "kube-policy-mcp-none", "no_opa no_kyverno")
		code, out := run(t, bin, example("kube-policy-mcp.yaml"), "packs")
		if code != 3 || !strings.Contains(out, "without any policy engine") {
			t.Errorf("exit %d\n%s", code, out)
		}
	})
}

// TestEnginesCanBeTurnedOffInConfig covers the run-time switch on the full build.
func TestEnginesCanBeTurnedOffInConfig(t *testing.T) {
	good := example("manifests", "compliant", "web.yaml")
	off := "engines:\n  kyverno:\n    enabled: false\n"

	code, out := run(t, binary, writeConfig(t, off, [2]string{"opa", "rego"}), "evaluate", "-f", good)
	if code != 0 || !strings.Contains(out, "against 6 policy(ies)") {
		t.Errorf("opa pack with kyverno off: exit %d\n%s", code, out)
	}
	// A pack that needs the disabled engine is refused, with the reason.
	code, out = run(t, binary, writeConfig(t, off, [2]string{"opa", "rego"}, [2]string{"kyverno", "kyverno"}), "evaluate", "-f", good)
	if code != 3 || !strings.Contains(out, "turned off in the configuration") {
		t.Errorf("pack needing a disabled engine: exit %d\n%s", code, out)
	}
	code, out = run(t, binary, writeConfig(t, "engines:\n  kyverno:\n    enabled: false\n  opa:\n    enabled: false\n", [2]string{"opa", "rego"}), "packs")
	if code != 3 || !strings.Contains(out, "every policy engine is turned off") {
		t.Errorf("all engines off: exit %d\n%s", code, out)
	}
	code, out = run(t, binary, writeConfig(t, "engines:\n  gatekeeper: {}\n", [2]string{"opa", "rego"}), "packs")
	if code != 3 || !strings.Contains(out, `engine "gatekeeper", which is not part of this build`) && !strings.Contains(out, `mentions engine "gatekeeper"`) {
		t.Errorf("unknown engine in config: exit %d\n%s", code, out)
	}

	// The full build reports both engines, with the disabled one marked.
	cmd := exec.Command(binary, "serve", "--config", writeConfig(t, off, [2]string{"opa", "rego"}))
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-test", Version: "0"}, nil)
	session, err := client.Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var packs struct {
		Engines       []string `json:"engines"`
		EngineDetails []struct {
			Name    string
			Enabled bool
		} `json:"engineDetails"`
	}
	call(t, session, "list_policy_packs", nil, &packs)
	state := map[string]bool{}
	for _, e := range packs.EngineDetails {
		state[e.Name] = e.Enabled
	}
	if strings.Join(packs.Engines, ",") != "opa" || len(state) != 2 || state["kyverno"] || !state["opa"] {
		t.Errorf("engines = %v details = %v", packs.Engines, state)
	}
}
