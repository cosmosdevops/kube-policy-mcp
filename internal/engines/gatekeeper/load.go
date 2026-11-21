// Package gatekeeper is the OPA Gatekeeper adapter. It embeds the Gatekeeper
// constraint framework (the code the Gatekeeper webhook and the gator CLI
// use) rather than flattening constraints into plain Rego policies.
//
// The unit of enforcement in Gatekeeper is the constraint: a ConstraintTemplate
// holds the logic, and a constraint says where it applies, with which
// parameters and with which enforcement action. So each constraint is one
// policy here.
package gatekeeper

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis"
	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	configv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/config/v1alpha1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/drivers/k8scel"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/gator/reader"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// Annotations read from a constraint first, then from its template.
const (
	annTitle           = "kubepolicy.cosmos.dev/title"
	annDescription     = "kubepolicy.cosmos.dev/description"
	annSeverity        = "kubepolicy.cosmos.dev/severity"
	annCategory        = "kubepolicy.cosmos.dev/category"
	annRemediation     = "kubepolicy.cosmos.dev/remediation"
	annDocs            = "kubepolicy.cosmos.dev/docs"
	annVersion         = "kubepolicy.cosmos.dev/version"
	annRequiredContext = "kubepolicy.cosmos.dev/required-context"
	// The Gatekeeper policy library uses these on templates.
	annLibraryTitle       = "metadata.gatekeeper.sh/title"
	annLibraryDescription = "description"
	annLibraryVersion     = "metadata.gatekeeper.sh/version"
)

const (
	groupConstraints = "constraints.gatekeeper.sh"
	groupExpansion   = "expansion.gatekeeper.sh"
	groupMutations   = "mutations.gatekeeper.sh"

	typeConstraint = "Constraint"
	typeTemplate   = "ConstraintTemplate"

	ruleViolation = "violation"

	// Gatekeeper enforcement actions.
	actionDeny   = "deny"
	actionWarn   = "warn"
	actionDryRun = "dryrun"
	actionScoped = "scoped"
)

// deniedBuiltins can reach the network or the host environment.
var deniedBuiltins = []string{"http.send", "net.lookup_ip_addr", "opa.runtime"}

var (
	reExternalData = regexp.MustCompile(`\bexternal_data\s*\(`)
	reInventory    = regexp.MustCompile(`\bdata\s*\.\s*inventory\b`)
)

var scheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	if err := apis.AddToScheme(s); err != nil {
		panic(err)
	}
	return s
}()

// loadedTemplate is one ConstraintTemplate of a source.
type loadedTemplate struct {
	name     string
	kind     string
	file     string
	raw      string
	obj      *unstructured.Unstructured
	template *templates.ConstraintTemplate
	problem  string
	// Static facts about the template's code.
	usesInventory, usesExternalData bool
}

// unit is one loaded policy source.
type unit struct {
	path      string
	templates map[string]*loadedTemplate // by constraint kind
	// expansion holds ExpansionTemplates and the mutators applied to the
	// resources they generate.
	expansion     []*unstructured.Unstructured
	hasExpansions bool
	// configs holds the Config resources, which can exclude namespaces.
	configs []*configv1alpha1.Config
}

// native is the engine-private state attached to each policy.
type native struct {
	unit       *unit
	constraint *unstructured.Unstructured
	template   *loadedTemplate
	// usesNamespaceSelector is true when the constraint matches on
	// namespace labels.
	usesNamespaceSelector bool
	// atAdmission is false when the constraint has no enforcement action
	// for the admission webhook.
	atAdmission bool
}

// Engine is the Gatekeeper adapter.
type Engine struct{}

// New returns the Gatekeeper adapter.
func New() *Engine { return &Engine{} }

// Name implements policy.Engine.
func (*Engine) Name() string { return EngineName }

// SupportedPolicyTypes implements policy.Engine.
func (*Engine) SupportedPolicyTypes() []string {
	return []string{typeTemplate, typeConstraint, "ExpansionTemplate", "Config"}
}

// newClient builds a constraint framework client the way Gatekeeper does:
// the Kubernetes CEL driver first, then the Rego driver, for the admission
// enforcement point. Network builtins are removed.
func newClient() (*constraintclient.Client, *target.K8sValidationTarget, error) {
	celDriver, err := k8scel.New()
	if err != nil {
		return nil, nil, fmt.Errorf("creating the Kubernetes CEL driver: %w", err)
	}
	regoDriver, err := rego.New(rego.DisableBuiltins(deniedBuiltins...))
	if err != nil {
		return nil, nil, fmt.Errorf("creating the Rego driver: %w", err)
	}
	handler := &target.K8sValidationTarget{}
	c, err := constraintclient.NewClient(
		constraintclient.Targets(handler),
		constraintclient.Driver(celDriver),
		constraintclient.Driver(regoDriver),
		constraintclient.EnforcementPoints(util.WebhookEnforcementPoint),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating the constraint client: %w", err)
	}
	return c, handler, nil
}

type constraintDoc struct {
	file, raw string
	obj       *unstructured.Unstructured
}

// LoadSource implements policy.Engine. path is a directory of manifests.
// Only local files are read.
func (e *Engine) LoadSource(ctx context.Context, path string, lim policy.Limits) (policy.LoadResult, error) {
	var res policy.LoadResult
	u := &unit{path: path, templates: map[string]*loadedTemplate{}}
	var constraints []constraintDoc
	var tmpls []*loadedTemplate
	count := 0
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != path && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(name))
		if !d.Type().IsRegular() || (ext != ".yaml" && ext != ".yml" && ext != ".json") {
			return nil
		}
		count++
		if lim.MaxPolicyFiles > 0 && count > lim.MaxPolicyFiles {
			return fmt.Errorf("more than %d policy files", lim.MaxPolicyFiles)
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if lim.MaxPolicyBytes > 0 && fi.Size() > lim.MaxPolicyBytes {
			return fmt.Errorf("%s is larger than the %d byte policy limit", p, lim.MaxPolicyBytes)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(path, p)
		docs := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
		for idx := 0; ; idx++ {
			raw, err := docs.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: unreadable document %d: %v", rel, idx, err))
				break
			}
			var content map[string]any
			if err := yaml.Unmarshal(raw, &content); err != nil {
				res.Policies = append(res.Policies, broken(u, p, fmt.Sprintf("%s#%d", rel, idx), string(raw), "invalid YAML: "+err.Error()))
				continue
			}
			if len(content) == 0 {
				continue
			}
			obj := &unstructured.Unstructured{Object: content}
			group, kind := obj.GroupVersionKind().Group, obj.GetKind()
			switch {
			case reader.IsTemplate(obj):
				tmpls = append(tmpls, &loadedTemplate{name: obj.GetName(), file: p, raw: string(raw), obj: obj})
			case group == groupConstraints:
				constraints = append(constraints, constraintDoc{file: p, raw: string(raw), obj: obj})
			case reader.IsConfig(obj):
				var cfg configv1alpha1.Config
				if err := runtime.DefaultUnstructuredConverter.FromUnstructured(content, &cfg); err != nil {
					res.Policies = append(res.Policies, broken(u, p, "Config/"+obj.GetName(), string(raw), "invalid Config: "+err.Error()))
					continue
				}
				u.configs = append(u.configs, &cfg)
			case group == groupExpansion && kind == "ExpansionTemplate":
				u.expansion = append(u.expansion, obj)
				u.hasExpansions = true
			case group == groupMutations:
				u.expansion = append(u.expansion, obj)
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: mutator %s %s is only applied to resources generated by an ExpansionTemplate", rel, kind, obj.GetName()))
			case strings.HasSuffix(group, "gatekeeper.sh"):
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: ignored %s %s (not used for offline evaluation)", rel, kind, obj.GetName()))
			default:
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: ignored %s %s (not a Gatekeeper resource)", rel, obj.GetAPIVersion(), kind))
			}
		}
		return nil
	})
	if err != nil {
		return res, err
	}

	// Validate templates and constraints by adding them to a client, which
	// compiles the template code and checks constraints against the
	// template's parameter schema.
	client, _, err := newClient()
	if err != nil {
		return res, err
	}
	sort.Slice(tmpls, func(i, j int) bool { return tmpls[i].name < tmpls[j].name })
	for _, t := range tmpls {
		t.usesInventory = reInventory.MatchString(t.raw)
		t.usesExternalData = reExternalData.MatchString(t.raw)
		if err := addTemplate(ctx, client, t); err != nil && !t.usesExternalData {
			// external_data is not defined offline, so such a template never
			// compiles. That is reported as unsupported, not as broken.
			t.problem = err.Error()
		}
		if t.kind == "" {
			// Without a kind no constraint can refer to the template.
			res.Policies = append(res.Policies, broken(u, t.file, typeTemplate+"/"+t.name, t.raw, "invalid ConstraintTemplate: "+t.problem))
			continue
		}
		if dup, ok := u.templates[t.kind]; ok {
			t.problem = fmt.Sprintf("constraint kind %s is defined by two templates in %s: %s and %s", t.kind, path, dup.name, t.name)
			dup.problem = t.problem
			continue
		}
		u.templates[t.kind] = t
	}

	used := map[string]bool{}
	for _, c := range constraints {
		p := loadConstraint(ctx, client, u, c)
		if n, ok := p.Native.(*native); ok && n.template != nil {
			used[n.template.kind] = true
		}
		res.Policies = append(res.Policies, p)
	}
	for kind, t := range u.templates {
		if used[kind] {
			continue
		}
		rel, _ := filepath.Rel(path, t.file)
		if t.problem != "" {
			// A broken template must never go unnoticed.
			res.Policies = append(res.Policies, broken(u, t.file, typeTemplate+"/"+t.name, t.raw, "invalid ConstraintTemplate: "+t.problem))
			continue
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: ConstraintTemplate %s is not used by any constraint in this source, so it enforces nothing", rel, t.name))
	}

	// Two policies with the same identity in one source would shadow each other.
	seen := map[string]int{}
	for i := range res.Policies {
		seen[res.Policies[i].ID]++
	}
	var out []policy.Policy
	done := map[string]bool{}
	for _, p := range res.Policies {
		if done[p.ID] {
			continue
		}
		done[p.ID] = true
		if seen[p.ID] > 1 {
			p.LoadError, p.Supported = true, false
			p.Problem = fmt.Sprintf("policy %s is defined %d times in %s", p.ID, seen[p.ID], path)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	res.Policies = out
	sort.Strings(res.Warnings)
	return res, nil
}

// addTemplate converts a template and adds it to the client. It sets the
// template's kind as soon as that is known.
func addTemplate(ctx context.Context, client *constraintclient.Client, t *loadedTemplate) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("constraint framework panicked: %v", r)
		}
	}()
	t.kind, _, _ = unstructured.NestedString(t.obj.Object, "spec", "crd", "spec", "names", "kind")
	tmpl, err := reader.ToTemplate(scheme, t.obj.DeepCopy())
	if err != nil {
		return err
	}
	t.template = tmpl
	_, err = client.AddTemplate(ctx, tmpl)
	return err
}

func addConstraint(ctx context.Context, client *constraintclient.Client, c *unstructured.Unstructured) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("constraint framework panicked: %v", r)
		}
	}()
	_, err = client.AddConstraint(ctx, c.DeepCopy())
	return err
}

func broken(u *unit, file, name, raw, problem string) policy.Policy {
	return policy.Policy{ID: EngineName + "/" + name, Name: name, Engine: EngineName, Type: "unknown", SourcePath: file, Problem: problem, LoadError: true, Raw: raw, Native: &native{unit: u}}
}

func loadConstraint(ctx context.Context, client *constraintclient.Client, u *unit, doc constraintDoc) policy.Policy {
	c := doc.obj
	kind, name := c.GetKind(), c.GetName()
	p := policy.Policy{
		ID: EngineName + "/" + kind + "/" + name, Name: name, Engine: EngineName, Type: typeConstraint,
		SourcePath: doc.file, Raw: doc.raw,
	}
	n := &native{unit: u, constraint: c}
	p.Native = n
	fail := func(msg string) policy.Policy {
		p.Problem, p.LoadError = msg, true
		return p
	}
	if kind == "" || name == "" {
		p.ID = EngineName + "/" + typeConstraint + "/" + filepath.Base(doc.file)
		return fail("constraint has no kind or no metadata.name")
	}
	t, ok := u.templates[kind]
	if !ok {
		return fail(fmt.Sprintf("no ConstraintTemplate for kind %s in this source. A constraint and its template must be in the same source", kind))
	}
	n.template = t
	p.Raw = trimDoc(doc.raw) + "\n---\n" + trimDoc(t.raw) + "\n"

	// Metadata: the constraint's own annotations win over the template's.
	ann := func(keys ...string) string {
		for _, source := range []map[string]string{c.GetAnnotations(), t.obj.GetAnnotations()} {
			for _, k := range keys {
				if v := strings.TrimSpace(source[k]); v != "" {
					return v
				}
			}
		}
		return ""
	}
	p.Title = ann(annTitle, annLibraryTitle)
	p.Description = ann(annDescription, annLibraryDescription)
	p.Severity, p.Category = ann(annSeverity), ann(annCategory)
	p.Remediation = ann(annRemediation)
	p.Version = ann(annVersion, annLibraryVersion)
	p.Docs = splitList(ann(annDocs))
	p.RequiredContext = splitList(ann(annRequiredContext))

	var actions []string
	p.Enforcement, actions, n.atAdmission = enforcement(c)
	p.Rules = []policy.Rule{{ID: ruleViolation, Enforcement: p.Enforcement, Description: "violation rule of ConstraintTemplate " + t.name}}

	match := map[string]any{"template": t.name}
	if m, ok, _ := unstructured.NestedMap(c.Object, "spec", "match"); ok {
		match["match"] = m
	}
	if params, ok, _ := unstructured.NestedFieldNoCopy(c.Object, "spec", "parameters"); ok {
		match["parameters"] = params
	}
	match["enforcementAction"] = enforcementAction(c)
	if len(actions) > 0 {
		match["admissionActions"] = actions
	}
	p.Match = match
	p.Kinds = constraintKinds(c, u)

	need := func(k string) {
		if !slices.Contains(p.RequiredContext, k) {
			p.RequiredContext = append(p.RequiredContext, k)
		}
	}
	if sel, ok, _ := unstructured.NestedMap(c.Object, "spec", "match", "namespaceSelector"); ok && len(sel) > 0 {
		n.usesNamespaceSelector = true
		need("namespace.labels")
	}
	if t.usesInventory {
		need("resources")
	}

	if t.problem != "" {
		return fail(fmt.Sprintf("ConstraintTemplate %s could not be loaded: %s", t.name, t.problem))
	}
	if t.usesExternalData {
		p.Problem = fmt.Sprintf("cannot be evaluated offline: ConstraintTemplate %s calls external_data, which needs network access", t.name)
		return p
	}
	if err := addConstraint(ctx, client, c); err != nil {
		return fail("invalid constraint: " + err.Error())
	}
	p.Supported = true
	return p
}

func enforcementAction(c *unstructured.Unstructured) string {
	action, _, _ := unstructured.NestedString(c.Object, "spec", "enforcementAction")
	if action == "" {
		return actionDeny
	}
	return action
}

// enforcement works out what a constraint does at admission. It returns the
// engine-neutral enforcement, the Gatekeeper actions for the admission
// webhook, and whether the constraint acts at admission at all.
func enforcement(c *unstructured.Unstructured) (string, []string, bool) {
	action := enforcementAction(c)
	actions := []string{action}
	if action == actionScoped {
		actions = nil
		scoped, _, _ := unstructured.NestedSlice(c.Object, "spec", "scopedEnforcementActions")
		for _, item := range scoped {
			entry, _ := item.(map[string]any)
			a, _ := entry["action"].(string)
			points, _ := entry["enforcementPoints"].([]any)
			for _, pt := range points {
				pm, _ := pt.(map[string]any)
				if name, _ := pm["name"].(string); (name == util.WebhookEnforcementPoint || name == "*") && a != "" && !slices.Contains(actions, a) {
					actions = append(actions, strings.ToLower(a))
				}
			}
		}
		if len(actions) == 0 {
			return "", nil, false
		}
	}
	return neutralEnforcement(actions), actions, true
}

func neutralEnforcement(actions []string) string {
	switch {
	case slices.Contains(actions, actionDeny):
		return policy.EnforceDeny
	case slices.Contains(actions, actionWarn):
		return policy.EnforceWarn
	}
	return policy.EnforceAudit
}

// constraintKinds lists the kinds a constraint selects. When the source has
// ExpansionTemplates, the kinds that expand into a selected kind are added.
// An empty result means the kinds cannot be listed.
func constraintKinds(c *unstructured.Unstructured, u *unit) []string {
	entries, found, _ := unstructured.NestedSlice(c.Object, "spec", "match", "kinds")
	if !found || len(entries) == 0 {
		return nil
	}
	kinds := map[string]bool{}
	for _, e := range entries {
		entry, _ := e.(map[string]any)
		list, _ := entry["kinds"].([]any)
		if len(list) == 0 {
			return nil
		}
		for _, k := range list {
			s, _ := k.(string)
			if s == "*" || s == "" {
				return nil
			}
			kinds[s] = true
		}
	}
	for _, exp := range u.expansion {
		if exp.GroupVersionKind().Group != groupExpansion {
			continue
		}
		generated, _, _ := unstructured.NestedString(exp.Object, "spec", "generatedGVK", "kind")
		if !kinds[generated] {
			continue
		}
		applyTo, _, _ := unstructured.NestedSlice(exp.Object, "spec", "applyTo")
		for _, a := range applyTo {
			entry, _ := a.(map[string]any)
			list, _ := entry["kinds"].([]any)
			for _, k := range list {
				if s, _ := k.(string); s != "" && s != "*" {
					kinds[s] = true
				}
			}
		}
	}
	out := make([]string, 0, len(kinds))
	for k := range kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidatePolicy implements policy.Engine.
func (*Engine) ValidatePolicy(ctx context.Context, p policy.Policy) error {
	if p.LoadError || !p.Supported {
		return errors.New(p.Problem)
	}
	n, ok := p.Native.(*native)
	if !ok || n.constraint == nil || n.template == nil || n.template.template == nil {
		return errors.New("policy was not loaded by the gatekeeper engine")
	}
	client, _, err := newClient()
	if err != nil {
		return err
	}
	if _, err := client.AddTemplate(ctx, n.template.template.DeepCopy()); err != nil {
		return err
	}
	return addConstraint(ctx, client, n.constraint)
}

// trimDoc removes the document separators around one YAML document.
func trimDoc(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "---"))
	return strings.TrimSpace(strings.TrimSuffix(raw, "---"))
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}
