// Package vap is the adapter for Kubernetes ValidatingAdmissionPolicy. It
// embeds the Kubernetes API server admission code (the same code that runs
// in a cluster) rather than evaluating bare CEL expressions.
//
// A policy is only enforced through a ValidatingAdmissionPolicyBinding, so
// the adapter loads both and evaluates each policy through its bindings.
package vap

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

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	"k8s.io/apiserver/pkg/cel/environment"
	"sigs.k8s.io/yaml"

	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// Optional annotations read from a policy. Kubernetes defines no metadata
// annotations for admission policies, so these are this project's own.
const (
	annTitle           = "kubepolicy.dev/title"
	annDescription     = "kubepolicy.dev/description"
	annSeverity        = "kubepolicy.dev/severity"
	annCategory        = "kubepolicy.dev/category"
	annRemediation     = "kubepolicy.dev/remediation"
	annDocs            = "kubepolicy.dev/docs"
	annVersion         = "kubepolicy.dev/version"
	annRequiredContext = "kubepolicy.dev/required-context"
)

const (
	groupAdmReg = "admissionregistration.k8s.io"

	kindPolicy  = "ValidatingAdmissionPolicy"
	kindBinding = "ValidatingAdmissionPolicyBinding"
)

// unit is one loaded policy source.
type unit struct {
	path string
	// params are the non-policy objects of the source. A binding can refer
	// to them with paramRef.
	params []*unstructured.Unstructured
}

// native is the engine-private state attached to each policy.
type native struct {
	unit      *unit
	policy    *admissionregistrationv1.ValidatingAdmissionPolicy
	bindings  []*admissionregistrationv1.ValidatingAdmissionPolicyBinding
	validator validating.Validator
	// Static facts about the policy's expressions.
	usesNamespaceObject bool
}

// Engine is the ValidatingAdmissionPolicy adapter.
type Engine struct{}

// New returns the adapter.
func New() *Engine { return &Engine{} }

// Name implements policy.Engine.
func (*Engine) Name() string { return EngineName }

// SupportedPolicyTypes implements policy.Engine.
func (*Engine) SupportedPolicyTypes() []string { return []string{kindPolicy, kindBinding} }

var (
	reNamespaceObject = regexp.MustCompile(`(^|[^.\w])namespaceObject\b`)
	reUserInfo        = regexp.MustCompile(`(^|[^.\w])request\s*\.\s*userInfo\b`)
	reAuthorizer      = regexp.MustCompile(`(^|[^.\w])authorizer\b`)
)

type policyDoc struct {
	file, raw string
	obj       map[string]any
}

// LoadSource implements policy.Engine. path is a directory of manifests.
// Only local files are read.
func (e *Engine) LoadSource(_ context.Context, path string, lim policy.Limits) (policy.LoadResult, error) {
	var res policy.LoadResult
	u := &unit{path: path}
	var policies []policyDoc
	bindings := map[string][]*admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
	bindingFiles := map[string]string{}
	bindingRaw := map[string]string{}
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
		reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
		for idx := 0; ; idx++ {
			raw, err := reader.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: unreadable document %d: %v", rel, idx, err))
				break
			}
			var obj map[string]any
			if err := yaml.Unmarshal(raw, &obj); err != nil {
				res.Policies = append(res.Policies, broken(u, p, fmt.Sprintf("%s#%d", rel, idx), string(raw), "invalid YAML: "+err.Error()))
				continue
			}
			if len(obj) == 0 {
				continue
			}
			apiVersion, _ := obj["apiVersion"].(string)
			kind, _ := obj["kind"].(string)
			group, _, hasGroup := strings.Cut(apiVersion, "/")
			if !hasGroup {
				group = ""
			}
			md, _ := obj["metadata"].(map[string]any)
			pname, _ := md["name"].(string)
			switch {
			case group == groupAdmReg && kind == kindPolicy:
				policies = append(policies, policyDoc{file: p, raw: string(raw), obj: obj})
			case group == groupAdmReg && kind == kindBinding:
				var b admissionregistrationv1.ValidatingAdmissionPolicyBinding
				if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(obj, &b, true); err != nil {
					res.Policies = append(res.Policies, broken(u, p, kindBinding+"/"+pname, string(raw), "invalid binding: "+err.Error()))
					continue
				}
				if msg := checkBinding(&b); msg != "" {
					res.Policies = append(res.Policies, broken(u, p, kindBinding+"/"+pname, string(raw), "invalid binding: "+msg))
					continue
				}
				defaultMatch(b.Spec.MatchResources)
				bindings[b.Spec.PolicyName] = append(bindings[b.Spec.PolicyName], &b)
				bindingFiles[b.Name] = rel
				bindingRaw[b.Name] = string(raw)
			case group == groupAdmReg && strings.HasPrefix(kind, "MutatingAdmissionPolicy"):
				if kind == "MutatingAdmissionPolicy" {
					res.Policies = append(res.Policies, policy.Policy{
						ID: EngineName + "/" + kind + "/" + pname, Name: pname, Engine: EngineName, Type: kind, SourcePath: p, Raw: string(raw),
						Problem: "MutatingAdmissionPolicy changes resources and is not evaluated offline", Native: &native{unit: u},
					})
				}
			case group == groupAdmReg:
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: ignored %s %s (admission webhooks are not evaluated)", rel, kind, pname))
			case apiVersion != "" && kind != "":
				// Anything else may be a parameter object for a binding.
				u.params = append(u.params, &unstructured.Unstructured{Object: obj})
			default:
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: ignored document %d (no apiVersion or kind)", rel, idx))
			}
		}
		return nil
	})
	if err != nil {
		return res, err
	}

	known := map[string]bool{}
	for _, doc := range policies {
		md, _ := doc.obj["metadata"].(map[string]any)
		name, _ := md["name"].(string)
		known[name] = true
		bs := bindings[name]
		sort.Slice(bs, func(i, j int) bool { return bs[i].Name < bs[j].Name })
		// The definition of a policy includes the bindings that enforce it.
		doc.raw = trimDoc(doc.raw)
		for _, b := range bs {
			doc.raw += "\n---\n" + trimDoc(bindingRaw[b.Name])
		}
		doc.raw += "\n"
		res.Policies = append(res.Policies, loadPolicy(u, doc, name, bs))
	}
	for name, bs := range bindings {
		if known[name] {
			continue
		}
		for _, b := range bs {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: binding %s refers to policy %q, which is not in this source", bindingFiles[b.Name], b.Name, name))
		}
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

func broken(u *unit, file, name, raw, problem string) policy.Policy {
	return policy.Policy{ID: EngineName + "/" + name, Name: name, Engine: EngineName, Type: "unknown", SourcePath: file, Problem: problem, LoadError: true, Raw: raw, Native: &native{unit: u}}
}

// checkBinding applies the API server's required-field rules that matter
// for evaluation. It returns a message when the binding is invalid.
func checkBinding(b *admissionregistrationv1.ValidatingAdmissionPolicyBinding) string {
	switch {
	case b.Name == "":
		return "binding has no metadata.name"
	case b.Spec.PolicyName == "":
		return "spec.policyName is required"
	case len(b.Spec.ValidationActions) == 0:
		return "spec.validationActions is required"
	}
	for _, a := range b.Spec.ValidationActions {
		switch a {
		case admissionregistrationv1.Deny, admissionregistrationv1.Warn, admissionregistrationv1.Audit:
		default:
			return fmt.Sprintf("unknown validation action %q", a)
		}
	}
	if slices.Contains(b.Spec.ValidationActions, admissionregistrationv1.Deny) && slices.Contains(b.Spec.ValidationActions, admissionregistrationv1.Warn) {
		return "spec.validationActions must not contain both Deny and Warn"
	}
	if ref := b.Spec.ParamRef; ref != nil {
		if (ref.Name == "") == (ref.Selector == nil) {
			return "spec.paramRef needs exactly one of name or selector"
		}
	}
	return ""
}

// defaultMatch applies the API server defaults that matching relies on. An
// unset selector means "everything"; without the default the upstream
// matcher would treat it as "nothing".
func defaultMatch(m *admissionregistrationv1.MatchResources) {
	if m == nil {
		return
	}
	if m.NamespaceSelector == nil {
		m.NamespaceSelector = &metav1.LabelSelector{}
	}
	if m.ObjectSelector == nil {
		m.ObjectSelector = &metav1.LabelSelector{}
	}
	if m.MatchPolicy == nil {
		equivalent := admissionregistrationv1.Equivalent
		m.MatchPolicy = &equivalent
	}
	all := admissionregistrationv1.AllScopes
	for _, rules := range [][]admissionregistrationv1.NamedRuleWithOperations{m.ResourceRules, m.ExcludeResourceRules} {
		for i := range rules {
			if rules[i].Scope == nil {
				rules[i].Scope = &all
			}
		}
	}
}

func loadPolicy(u *unit, doc policyDoc, name string, bindings []*admissionregistrationv1.ValidatingAdmissionPolicyBinding) policy.Policy {
	p := policy.Policy{ID: EngineName + "/" + name, Name: name, Engine: EngineName, Type: kindPolicy, SourcePath: doc.file, Raw: doc.raw}
	n := &native{unit: u, bindings: bindings}
	p.Native = n
	fail := func(msg string) policy.Policy {
		p.Problem, p.LoadError = msg, true
		return p
	}
	if name == "" {
		return fail("policy has no metadata.name")
	}
	var typed admissionregistrationv1.ValidatingAdmissionPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(doc.obj, &typed, true); err != nil {
		return fail("invalid policy: " + err.Error())
	}
	spec := &typed.Spec
	switch {
	case spec.MatchConstraints == nil || len(spec.MatchConstraints.ResourceRules) == 0:
		return fail("invalid policy: spec.matchConstraints.resourceRules is required")
	case len(spec.Validations) == 0 && len(spec.AuditAnnotations) == 0:
		return fail("invalid policy: spec.validations or spec.auditAnnotations is required")
	}
	for i, rule := range spec.MatchConstraints.ResourceRules {
		if len(rule.Operations) == 0 || len(rule.Resources) == 0 || len(rule.APIGroups) == 0 || len(rule.APIVersions) == 0 {
			return fail(fmt.Sprintf("invalid policy: spec.matchConstraints.resourceRules[%d] needs apiGroups, apiVersions, operations and resources", i))
		}
	}
	defaultMatch(spec.MatchConstraints)
	n.policy = &typed

	ann := typed.GetAnnotations()
	p.Title, p.Description = ann[annTitle], strings.TrimSpace(ann[annDescription])
	p.Severity, p.Category = ann[annSeverity], ann[annCategory]
	p.Remediation, p.Version = strings.TrimSpace(ann[annRemediation]), ann[annVersion]
	p.Docs = splitList(ann[annDocs])
	p.RequiredContext = splitList(ann[annRequiredContext])

	p.Enforcement = enforcement(bindings)
	for i, v := range spec.Validations {
		msg := v.Message
		if msg == "" && v.MessageExpression != "" {
			msg = "(computed) " + v.MessageExpression
		}
		p.Rules = append(p.Rules, policy.Rule{ID: ruleID(i), Expression: v.Expression, Message: msg, Enforcement: p.Enforcement})
	}
	if specMap, ok := doc.obj["spec"].(map[string]any); ok {
		match := map[string]any{}
		for _, k := range []string{"matchConstraints", "matchConditions", "paramKind"} {
			if v, ok := specMap[k]; ok {
				match[k] = v
			}
		}
		var bound []any
		for _, b := range bindings {
			entry := map[string]any{"name": b.Name, "validationActions": b.Spec.ValidationActions}
			if b.Spec.MatchResources != nil {
				entry["matchResources"] = b.Spec.MatchResources
			}
			if b.Spec.ParamRef != nil {
				entry["paramRef"] = b.Spec.ParamRef
			}
			bound = append(bound, entry)
		}
		if len(bound) > 0 {
			match["bindings"] = bound
		}
		p.Match = match
	}

	kinds := map[string]bool{}
	if !addKinds(kinds, spec.MatchConstraints) {
		for k := range kinds {
			p.Kinds = append(p.Kinds, k)
		}
		sort.Strings(p.Kinds)
	}

	exprs := strings.Join(collectExpressions(doc.obj["spec"]), "\n")
	n.usesNamespaceObject = reNamespaceObject.MatchString(exprs)
	need := func(k string) {
		if !slices.Contains(p.RequiredContext, k) {
			p.RequiredContext = append(p.RequiredContext, k)
		}
	}
	selectors := []*admissionregistrationv1.MatchResources{spec.MatchConstraints}
	for _, b := range bindings {
		selectors = append(selectors, b.Spec.MatchResources)
	}
	for _, m := range selectors {
		if hasNamespaceSelector(m) {
			need("namespace.labels")
		}
	}
	if n.usesNamespaceObject {
		need("namespace.labels")
	}
	if reUserInfo.MatchString(exprs) {
		need("user")
	}

	// Compile now so that a broken policy is found at load time.
	validator, err := compile(&typed)
	if err != nil {
		return fail("policy does not compile: " + err.Error())
	}
	n.validator = validator
	switch {
	case reAuthorizer.MatchString(exprs):
		p.Problem = "cannot be evaluated offline: the policy uses the authorizer variable, and RBAC checks need a live cluster"
	case len(bindings) == 0:
		p.Problem = "no ValidatingAdmissionPolicyBinding in this source refers to the policy, so it is not enforced. Add a binding or remove the policy"
	}
	if p.Problem != "" {
		return p
	}
	p.Supported = true
	return p
}

func ruleID(i int) string { return fmt.Sprintf("validations[%d]", i) }

// enforcement gives the strongest action over all bindings of a policy.
func enforcement(bindings []*admissionregistrationv1.ValidatingAdmissionPolicyBinding) string {
	out := ""
	for _, b := range bindings {
		switch e := bindingEnforcement(b); {
		case e == policy.EnforceDeny:
			return e
		case e == policy.EnforceWarn || out == "":
			out = e
		}
	}
	return out
}

func bindingEnforcement(b *admissionregistrationv1.ValidatingAdmissionPolicyBinding) string {
	switch {
	case slices.Contains(b.Spec.ValidationActions, admissionregistrationv1.Deny):
		return policy.EnforceDeny
	case slices.Contains(b.Spec.ValidationActions, admissionregistrationv1.Warn):
		return policy.EnforceWarn
	}
	return policy.EnforceAudit
}

// compile builds the upstream validator for a policy. It follows the
// unexported compilePolicy function of the API server plugin step by step.
//
// The upstream validator only reports a bad expression when it is evaluated,
// so each expression is also compiled here to find the error at load time.
func compile(p *admissionregistrationv1.ValidatingAdmissionPolicy) (v validating.Validator, err error) {
	failurePolicy := p.Spec.FailurePolicy
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("CEL compiler panicked: %v", r)
		}
	}()
	hasParam := p.Spec.ParamKind != nil
	optionalVars := cel.OptionalVariableDeclarations{HasParams: hasParam, HasAuthorizer: true}
	expressionOptionalVars := cel.OptionalVariableDeclarations{HasParams: hasParam, HasAuthorizer: false}
	compiler, err := cel.NewCompositedCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
	if err != nil {
		return nil, err
	}
	var problems []string
	check := func(where string, accessor cel.ExpressionAccessor, opts cel.OptionalVariableDeclarations) {
		if res := compiler.CompileCELExpression(accessor, opts, environment.StoredExpressions); res.Error != nil {
			problems = append(problems, where+": "+res.Error.Error())
		}
	}
	for i, variable := range p.Spec.Variables {
		accessor := &validating.Variable{Name: variable.Name, Expression: variable.Expression}
		if res := compiler.CompileAndStoreVariable(accessor, optionalVars, environment.StoredExpressions); res.Error != nil {
			problems = append(problems, fmt.Sprintf("variables[%d] (%s): %s", i, variable.Name, res.Error.Error()))
		}
	}

	var matcher matchconditions.Matcher
	if mcs := p.Spec.MatchConditions; len(mcs) > 0 {
		accessors := make([]cel.ExpressionAccessor, len(mcs))
		for i := range mcs {
			accessors[i] = (*matchconditions.MatchCondition)(&mcs[i])
			check(fmt.Sprintf("matchConditions[%d]", i), accessors[i], optionalVars)
		}
		matcher = matchconditions.NewMatcher(compiler.CompileCondition(accessors, optionalVars, environment.StoredExpressions), failurePolicy, "policy", "validate", p.Name)
	}
	validations := make([]cel.ExpressionAccessor, len(p.Spec.Validations))
	messages := make([]cel.ExpressionAccessor, len(p.Spec.Validations))
	for i, val := range p.Spec.Validations {
		validations[i] = &validating.ValidationCondition{Expression: val.Expression, Message: val.Message, Reason: val.Reason}
		check(fmt.Sprintf("validations[%d].expression", i), validations[i], optionalVars)
		if val.MessageExpression != "" {
			messages[i] = &validating.MessageExpressionCondition{MessageExpression: val.MessageExpression}
			check(fmt.Sprintf("validations[%d].messageExpression", i), messages[i], expressionOptionalVars)
		}
	}
	audits := make([]cel.ExpressionAccessor, len(p.Spec.AuditAnnotations))
	for i, a := range p.Spec.AuditAnnotations {
		audits[i] = &validating.AuditAnnotationCondition{Key: a.Key, ValueExpression: a.ValueExpression}
		check(fmt.Sprintf("auditAnnotations[%d].valueExpression", i), audits[i], optionalVars)
	}
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "; "))
	}
	v = validating.NewValidator(
		compiler.CompileCondition(validations, optionalVars, environment.StoredExpressions),
		matcher,
		compiler.CompileCondition(audits, optionalVars, environment.StoredExpressions),
		compiler.CompileCondition(messages, expressionOptionalVars, environment.StoredExpressions),
		failurePolicy,
		nil,
	)
	return v, v.CompileError()
}

// ValidatePolicy implements policy.Engine.
func (*Engine) ValidatePolicy(_ context.Context, p policy.Policy) error {
	if p.LoadError || !p.Supported {
		return errors.New(p.Problem)
	}
	n, ok := p.Native.(*native)
	if !ok || n.policy == nil || n.validator == nil {
		return errors.New("policy was not loaded by the vap engine")
	}
	return n.validator.CompileError()
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

// kindByResource maps common resource plurals to kinds for display. Unknown
// plurals are shown as written, since no cluster is available for discovery.
var kindByResource = map[string]string{
	"pods": "Pod", "deployments": "Deployment", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet",
	"replicasets": "ReplicaSet", "replicationcontrollers": "ReplicationController", "jobs": "Job", "cronjobs": "CronJob",
	"services": "Service", "configmaps": "ConfigMap", "secrets": "Secret", "namespaces": "Namespace",
	"ingresses": "Ingress", "networkpolicies": "NetworkPolicy", "serviceaccounts": "ServiceAccount",
	"persistentvolumeclaims": "PersistentVolumeClaim", "persistentvolumes": "PersistentVolume",
	"roles": "Role", "rolebindings": "RoleBinding", "clusterroles": "ClusterRole", "clusterrolebindings": "ClusterRoleBinding",
	"horizontalpodautoscalers": "HorizontalPodAutoscaler", "poddisruptionbudgets": "PodDisruptionBudget",
	"podtemplates": "PodTemplate", "nodes": "Node",
}

// addKinds records the kinds a match selects. It returns true when the match
// uses a wildcard, meaning the kinds cannot be listed.
func addKinds(kinds map[string]bool, m *admissionregistrationv1.MatchResources) bool {
	wildcard := false
	for _, rr := range m.ResourceRules {
		for _, res := range rr.Resources {
			base, _, _ := strings.Cut(res, "/")
			if base == "*" {
				wildcard = true
				continue
			}
			if k, ok := kindByResource[strings.ToLower(base)]; ok {
				kinds[k] = true
			} else {
				kinds[base] = true
			}
		}
	}
	return wildcard
}

func hasNamespaceSelector(m *admissionregistrationv1.MatchResources) bool {
	if m == nil || m.NamespaceSelector == nil {
		return false
	}
	return len(m.NamespaceSelector.MatchLabels) > 0 || len(m.NamespaceSelector.MatchExpressions) > 0
}

// collectExpressions gathers every CEL expression string in a policy spec.
func collectExpressions(v any) []string {
	var out []string
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s, ok := t[k].(string); ok && (k == "expression" || k == "messageExpression" || k == "valueExpression") {
				out = append(out, s)
				continue
			}
			out = append(out, collectExpressions(t[k])...)
		}
	case []any:
		for _, x := range t {
			out = append(out, collectExpressions(x)...)
		}
	}
	return out
}
