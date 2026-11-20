// Package kyverno is the Kyverno policy engine adapter. It embeds the
// upstream Kyverno CEL policy engine (the same code the Kyverno CLI and
// admission controller use) rather than re-implementing Kyverno semantics.
//
// Supported offline: ValidatingPolicy, NamespacedValidatingPolicy and
// PolicyException from the policies.kyverno.io API group. Kyverno 1.20
// removed the legacy kyverno.io ClusterPolicy and Policy kinds, so those are
// reported as unsupported instead of being evaluated.
package kyverno

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
	"sync"

	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	vpolautogen "github.com/kyverno/kyverno/pkg/cel/policies/vpol/autogen"
	vpolcompiler "github.com/kyverno/kyverno/pkg/cel/policies/vpol/compiler"
	vpolengine "github.com/kyverno/kyverno/pkg/cel/policies/vpol/engine"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// Annotation keys read from policies.
const (
	annTitle       = "policies.kyverno.io/title"
	annDescription = "policies.kyverno.io/description"
	annSeverity    = "policies.kyverno.io/severity"
	annCategory    = "policies.kyverno.io/category"
	// The kubepolicy.dev annotations are optional extras this project reads.
	annRemediation     = "kubepolicy.dev/remediation"
	annDocs            = "kubepolicy.dev/docs"
	annVersion         = "kubepolicy.dev/version"
	annRequiredContext = "kubepolicy.dev/required-context"
)

const (
	groupPolicies = "policies.kyverno.io"
	groupLegacy   = "kyverno.io"
	groupAdmReg   = "admissionregistration.k8s.io"
)

// unit is one loaded policy source.
type unit struct {
	path       string
	exceptions []*policiesv1beta1.PolicyException
}

// native is the engine-private state attached to each policy.
type native struct {
	unit   *unit
	policy policiesv1beta1.ValidatingPolicyLike
	// namespace is set for NamespacedValidatingPolicy.
	namespace string
	// Static facts about the policy's expressions.
	usesNamespaceSelector bool
	usesNamespaceObject   bool
	usesResourceLookup    bool
	usesGlobalContext     bool
	// offlineBlocker is set when the policy uses a feature that cannot run
	// offline (network or registry access).
	offlineBlocker string

	mu       sync.Mutex
	compiled map[string]vpolengine.Provider
}

// Engine is the Kyverno adapter.
type Engine struct {
	// evalMu serialises evaluation because the upstream CEL libraries keep
	// some process-wide state.
	evalMu sync.Mutex
}

// New returns the Kyverno adapter.
func New() *Engine { return &Engine{} }

// Name implements policy.Engine.
func (*Engine) Name() string { return EngineName }

// SupportedPolicyTypes implements policy.Engine.
func (*Engine) SupportedPolicyTypes() []string {
	return []string{"ValidatingPolicy", "NamespacedValidatingPolicy", "PolicyException"}
}

var (
	reNamespaceObject = regexp.MustCompile(`(^|[^.\w])namespaceObject\b`)
	reResourceLookup  = regexp.MustCompile(`(^|[^.\w])resource\s*\.\s*(Get|List)\s*\(`)
	reGlobalContext   = regexp.MustCompile(`(^|[^.\w])globalContext\b`)
	reUserInfo        = regexp.MustCompile(`(^|[^.\w])request\s*\.\s*userInfo\b`)
	// The checks below decide whether a policy may run at all, so they are
	// deliberately broad: they match the method names wherever they appear,
	// which also catches a library reached through a variable alias.
	reHTTP          = regexp.MustCompile(`(^|[^.\w])http($|[^\w])`)
	reImage         = regexp.MustCompile(`\.\s*GetMetadata\s*\(`)
	reResourceWrite = regexp.MustCompile(`\.\s*(Post|ToGVR)\s*\(`)
)

// usesHTTP reports whether the expressions refer to the http library. A
// policy that does must not run, because the upstream library would make
// real network calls. URLs inside string literals ("http://...") are not
// counted; any other bare "http" word is, even inside a string, because
// blocking too much is the safe direction here.
func usesHTTP(exprs string) bool {
	for _, loc := range reHTTP.FindAllStringIndex(exprs, -1) {
		// after is the text that follows the word "http".
		after := exprs[strings.Index(exprs[loc[0]:loc[1]], "http")+loc[0]+len("http"):]
		if strings.HasPrefix(after, "://") {
			continue
		}
		return true
	}
	return false
}

// LoadSource implements policy.Engine. path is a directory of Kyverno policy
// manifests. Only local files are read.
func (e *Engine) LoadSource(ctx context.Context, path string, lim policy.Limits) (policy.LoadResult, error) {
	var res policy.LoadResult
	u := &unit{path: path}
	type excDoc struct {
		ex   *policiesv1beta1.PolicyException
		file string
	}
	var exceptions []excDoc
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
			group := apiVersion
			if i := strings.Index(apiVersion, "/"); i >= 0 {
				group = apiVersion[:i]
			}
			md, _ := obj["metadata"].(map[string]any)
			pname, _ := md["name"].(string)
			pns, _ := md["namespace"].(string)
			switch {
			case group == groupPolicies && kind == "PolicyException":
				var ex policiesv1beta1.PolicyException
				if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(obj, &ex, true); err != nil {
					res.Policies = append(res.Policies, broken(u, p, "PolicyException/"+pname, string(raw), "invalid PolicyException: "+err.Error()))
					continue
				}
				if errs := ex.Validate(); len(errs) > 0 {
					res.Policies = append(res.Policies, broken(u, p, "PolicyException/"+pname, string(raw), "invalid PolicyException: "+errs.ToAggregate().Error()))
					continue
				}
				exceptions = append(exceptions, excDoc{&ex, p})
			case group == groupPolicies && (kind == "ValidatingPolicy" || kind == "NamespacedValidatingPolicy"):
				res.Policies = append(res.Policies, e.loadValidating(u, p, kind, pname, pns, obj, string(raw)))
			case group == groupPolicies:
				res.Policies = append(res.Policies, unsupported(u, p, kind, pname, pns, string(raw),
					fmt.Sprintf("%s is not a validation policy that can be evaluated offline; only ValidatingPolicy and NamespacedValidatingPolicy are supported", kind)))
			case group == groupLegacy && (kind == "ClusterPolicy" || kind == "Policy" || kind == "PolicyException"):
				res.Policies = append(res.Policies, unsupported(u, p, kind, pname, pns, string(raw),
					fmt.Sprintf("legacy %s %s is not supported: Kyverno 1.20 removed the kyverno.io policy kinds. Migrate it to a policies.kyverno.io ValidatingPolicy", apiVersion, kind)))
			case group == groupAdmReg && strings.HasPrefix(kind, "ValidatingAdmissionPolicy"):
				res.Policies = append(res.Policies, unsupported(u, p, kind, pname, pns, string(raw),
					"Kubernetes ValidatingAdmissionPolicy evaluation is not implemented yet (planned CEL adapter)"))
			default:
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: ignored %s %s (not a Kyverno policy)", rel, apiVersion, kind))
			}
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	sort.Slice(exceptions, func(i, j int) bool {
		return exceptions[i].ex.Namespace+"/"+exceptions[i].ex.Name < exceptions[j].ex.Namespace+"/"+exceptions[j].ex.Name
	})
	for _, x := range exceptions {
		u.exceptions = append(u.exceptions, x.ex)
		for i := range res.Policies {
			pol := &res.Policies[i]
			for _, ref := range x.ex.Spec.PolicyRefs {
				if ref.Name == pol.Name && ref.Kind == pol.Type {
					info := policy.ExceptionInfo{Name: exceptionKey(x.ex), SourcePath: x.file}
					for _, mc := range x.ex.Spec.MatchConditions {
						info.Conditions = append(info.Conditions, mc.Expression)
					}
					pol.Exceptions = append(pol.Exceptions, info)
				}
			}
		}
	}
	// Two policies with the same identity in one source would shadow each other.
	seen := map[string]int{}
	for i := range res.Policies {
		seen[res.Policies[i].ID]++
	}
	for i := range res.Policies {
		if p := &res.Policies[i]; seen[p.ID] > 1 && !p.LoadError {
			p.LoadError, p.Supported = true, false
			p.Problem = fmt.Sprintf("policy %s is defined %d times in %s", p.ID, seen[p.ID], path)
		}
	}
	res.Policies = dedupe(res.Policies)
	sort.Slice(res.Policies, func(i, j int) bool { return res.Policies[i].ID < res.Policies[j].ID })
	return res, nil
}

func dedupe(in []policy.Policy) []policy.Policy {
	seen := map[string]bool{}
	var out []policy.Policy
	for _, p := range in {
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	return out
}

func exceptionKey(ex *policiesv1beta1.PolicyException) string {
	if ex.Namespace != "" {
		return ex.Namespace + "/" + ex.Name
	}
	return ex.Name
}

func policyID(kind, name, ns string) string {
	if kind == "NamespacedValidatingPolicy" && ns != "" {
		return EngineName + "/" + ns + "/" + name
	}
	return EngineName + "/" + name
}

func broken(u *unit, file, name, raw, problem string) policy.Policy {
	return policy.Policy{ID: EngineName + "/" + name, Name: name, Engine: EngineName, Type: "unknown", SourcePath: file, Problem: problem, LoadError: true, Raw: raw, Native: &native{unit: u}}
}

func unsupported(u *unit, file, kind, name, ns, raw, problem string) policy.Policy {
	id := policyID(kind, name, ns)
	if kind != "ValidatingPolicy" && kind != "NamespacedValidatingPolicy" {
		id = EngineName + "/" + kind + "/" + name
	}
	return policy.Policy{ID: id, Name: name, Engine: EngineName, Type: kind, SourcePath: file, Problem: problem, Raw: raw, Native: &native{unit: u}}
}

func (e *Engine) loadValidating(u *unit, file, kind, name, ns string, obj map[string]any, raw string) policy.Policy {
	p := policy.Policy{ID: policyID(kind, name, ns), Name: name, Engine: EngineName, Type: kind, SourcePath: file, Raw: raw}
	n := &native{unit: u, compiled: map[string]vpolengine.Provider{}}
	p.Native = n
	fail := func(msg string) policy.Policy {
		p.Problem, p.LoadError = msg, true
		return p
	}
	if name == "" {
		return fail("policy has no metadata.name")
	}
	var typed policiesv1beta1.ValidatingPolicyLike
	if kind == "NamespacedValidatingPolicy" {
		var t policiesv1beta1.NamespacedValidatingPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(obj, &t, true); err != nil {
			return fail("invalid policy: " + err.Error())
		}
		if t.Namespace == "" {
			return fail("NamespacedValidatingPolicy has no metadata.namespace")
		}
		n.namespace = t.Namespace
		typed = &t
	} else {
		var t policiesv1beta1.ValidatingPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(obj, &t, true); err != nil {
			return fail("invalid policy: " + err.Error())
		}
		typed = &t
	}
	n.policy = typed
	spec := typed.GetValidatingPolicySpec()

	ann := typed.GetAnnotations()
	p.Title, p.Description = ann[annTitle], strings.TrimSpace(ann[annDescription])
	p.Severity, p.Category = ann[annSeverity], ann[annCategory]
	p.Remediation, p.Version = strings.TrimSpace(ann[annRemediation]), ann[annVersion]
	p.Docs = splitList(ann[annDocs])
	p.RequiredContext = splitList(ann[annRequiredContext])

	actions := spec.ValidationActions()
	switch {
	case slices.Contains(actions, admissionregistrationv1.Deny):
		p.Enforcement = policy.EnforceDeny
	case slices.Contains(actions, admissionregistrationv1.Warn):
		p.Enforcement = policy.EnforceWarn
	default:
		p.Enforcement = policy.EnforceAudit
	}
	for i, v := range spec.Validations {
		msg := v.Message
		if msg == "" && v.MessageExpression != "" {
			msg = "(computed) " + v.MessageExpression
		}
		p.Rules = append(p.Rules, policy.Rule{ID: fmt.Sprintf("validations[%d]", i), Expression: v.Expression, Message: msg, Enforcement: p.Enforcement})
	}
	if specMap, ok := obj["spec"].(map[string]any); ok {
		match := map[string]any{}
		for _, k := range []string{"matchConstraints", "matchConditions"} {
			if v, ok := specMap[k]; ok {
				match[k] = v
			}
		}
		if n.namespace != "" {
			match["namespace"] = n.namespace
		}
		p.Match = match
	}

	// Kinds: the policy's own resource rules plus the pod controllers that
	// Kyverno's autogen feature extends it to.
	kinds := map[string]bool{}
	wildcard := addKinds(kinds, spec.MatchConstraints)
	n.usesNamespaceSelector = hasNamespaceSelector(spec.MatchConstraints)
	if gen, err := vpolautogen.Autogen(typed); err == nil {
		for _, g := range gen {
			if g.Spec != nil {
				wildcard = addKinds(kinds, g.Spec.MatchConstraints) || wildcard
			}
		}
	}
	if !wildcard {
		for k := range kinds {
			p.Kinds = append(p.Kinds, k)
		}
		sort.Strings(p.Kinds)
	}

	exprs := strings.Join(collectExpressions(obj["spec"]), "\n")
	n.usesNamespaceObject = reNamespaceObject.MatchString(exprs)
	n.usesResourceLookup = reResourceLookup.MatchString(exprs)
	n.usesGlobalContext = reGlobalContext.MatchString(exprs)
	need := func(k string) {
		if !slices.Contains(p.RequiredContext, k) {
			p.RequiredContext = append(p.RequiredContext, k)
		}
	}
	if n.usesNamespaceSelector {
		need("namespace.labels")
	}
	if n.usesNamespaceObject {
		need("namespace")
	}
	if reUserInfo.MatchString(exprs) {
		need("user")
	}

	mode := string(spec.EvaluationMode())
	switch {
	case mode != "" && mode != "Kubernetes":
		p.Problem = fmt.Sprintf("evaluation mode %q is not supported; only Kubernetes mode policies are evaluated", mode)
	case usesHTTP(exprs):
		n.offlineBlocker = "the policy uses the http library, and network access is disabled"
	case reImage.MatchString(exprs):
		n.offlineBlocker = "the policy calls image.GetMetadata, which needs registry access"
	case reResourceWrite.MatchString(exprs):
		n.offlineBlocker = "the policy calls Post or ToGVR, which need a live cluster or network access"
	}
	if p.Problem != "" {
		return p
	}
	if n.offlineBlocker != "" {
		p.Problem = "cannot be evaluated offline: " + n.offlineBlocker
		return p
	}
	// Compile once now so that broken policies are found at load time.
	if _, err := n.provider(nil); err != nil {
		return fail(err.Error())
	}
	p.Supported = true
	return p
}

// provider compiles the policy together with the exceptions that target it.
// Results are cached per exception set.
func (n *native) provider(exceptions []*policiesv1beta1.PolicyException) (prov vpolengine.Provider, err error) {
	keys := make([]string, 0, len(exceptions))
	for _, ex := range exceptions {
		keys = append(keys, exceptionKey(ex)+"@"+ex.ResourceVersion+fmt.Sprintf("%p", ex))
	}
	key := strings.Join(keys, ",")
	n.mu.Lock()
	defer n.mu.Unlock()
	if p, ok := n.compiled[key]; ok {
		return p, nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("kyverno compiler panicked: %v", r)
		}
	}()
	p, err := vpolengine.NewProvider(vpolcompiler.NewCompiler(), []policiesv1beta1.ValidatingPolicyLike{n.policy}, exceptions)
	if err != nil {
		return nil, err
	}
	n.compiled[key] = p
	return p, nil
}

// ValidatePolicy implements policy.Engine.
func (*Engine) ValidatePolicy(_ context.Context, p policy.Policy) error {
	if p.LoadError || !p.Supported {
		return errors.New(p.Problem)
	}
	n, ok := p.Native.(*native)
	if !ok || n.policy == nil {
		return errors.New("policy was not loaded by the kyverno engine")
	}
	_, err := n.provider(nil)
	return err
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
	if m == nil {
		return true
	}
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
	return wildcard || len(m.ResourceRules) == 0
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
