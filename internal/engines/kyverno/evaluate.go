package kyverno

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	celengine "github.com/kyverno/kyverno/pkg/cel/engine"
	"github.com/kyverno/kyverno/pkg/cel/libs"
	"github.com/kyverno/kyverno/pkg/cel/matching"
	vpolengine "github.com/kyverno/kyverno/pkg/cel/policies/vpol/engine"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

const validationIndexKey = "cel.validationIndex"

// Evaluate implements policy.Engine. It builds a simulated admission request
// for each resource and runs it through the upstream Kyverno engine.
func (e *Engine) Evaluate(ctx context.Context, resources []manifests.Resource, policies []policy.Policy, ec evalctx.Context) ([]findings.Finding, error) {
	e.evalMu.Lock()
	defer e.evalMu.Unlock()

	// Exceptions from every source in the pack apply to every policy.
	var exceptions []*policiesv1beta1.PolicyException
	var notes []string
	seenUnit := map[*unit]bool{}
	seenEx := map[string]bool{}
	for _, p := range policies {
		n, _ := p.Native.(*native)
		if n == nil || n.unit == nil || seenUnit[n.unit] {
			continue
		}
		seenUnit[n.unit] = true
		for _, ex := range n.unit.exceptions {
			if ex.IsExpired() {
				notes = append(notes, exceptionKey(ex))
				continue
			}
			if !seenEx[exceptionKey(ex)] {
				seenEx[exceptionKey(ex)] = true
				exceptions = append(exceptions, ex)
			}
		}
	}
	sort.Slice(exceptions, func(i, j int) bool { return exceptionKey(exceptions[i]) < exceptionKey(exceptions[j]) })

	// The fake context provider serves resource.Get/List from the supplied
	// resources only. Nothing is fetched from a cluster.
	provider := libs.NewFakeContextProvider()
	objs := make([]*unstructured.Unstructured, len(resources))
	for i, r := range resources {
		u, err := toUnstructured(r.Object)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Source, err)
		}
		objs[i] = u
		addToContext(provider, u)
	}
	for i, obj := range ec.Resources {
		u, err := toUnstructured(obj)
		if err != nil {
			return nil, fmt.Errorf("context.resources[%d]: %w", i, err)
		}
		if u.GetKind() == "" || u.GetAPIVersion() == "" {
			return nil, fmt.Errorf("context.resources[%d] has no apiVersion or kind", i)
		}
		addToContext(provider, u)
	}
	for name, data := range ec.Data {
		provider.AddGlobalReference(name, data)
	}
	nsResolver := func(name string) *corev1.Namespace {
		ns, ok := ec.NamespaceFor(name)
		if !ok {
			return nil
		}
		out := &corev1.Namespace{}
		out.Name = ns.Name
		out.Labels = map[string]string{"kubernetes.io/metadata.name": ns.Name}
		for k, v := range ns.Labels {
			out.Labels[k] = v
		}
		out.Annotations = ns.Annotations
		return out
	}
	var user authenticationv1.UserInfo
	if ec.User != nil {
		user = authenticationv1.UserInfo{Username: ec.User.Username, UID: ec.User.UID, Groups: ec.User.Groups}
	}

	var out []findings.Finding
	for _, p := range policies {
		n, _ := p.Native.(*native)
		switch {
		case n == nil:
			out = append(out, forAll(p, resources, findings.StatusError, "policy was not loaded by the kyverno engine")...)
			continue
		case p.LoadError:
			out = append(out, forAll(p, resources, findings.StatusError, "policy could not be loaded: "+p.Problem)...)
			continue
		case !p.Supported:
			// Unsupported checks are unknown for the kinds they may apply to.
			for _, r := range resources {
				f := base(p, r)
				if !p.AppliesToKind(r.Kind()) {
					f.Status, f.Message = findings.StatusNotApplicable, "resource kind is not matched by the policy"
				} else {
					f.Status, f.Message = findings.StatusUnknown, "unsupported check: "+p.Problem
				}
				out = append(out, f)
			}
			continue
		}
		var matched []*policiesv1beta1.PolicyException
		for _, ex := range exceptions {
			for _, ref := range ex.Spec.PolicyRefs {
				if ref.Name == n.policy.GetName() && ref.Kind == n.policy.GetKind() {
					matched = append(matched, ex)
					break
				}
			}
		}
		prov, err := n.provider(matched)
		if err != nil {
			out = append(out, forAll(p, resources, findings.StatusError, "policy failed to compile: "+err.Error())...)
			continue
		}
		eng := vpolengine.NewEngine(prov, nsResolver, matching.NewMatcher())
		for i, r := range resources {
			if err := ctx.Err(); err != nil {
				f := base(p, r)
				f.Status, f.Message = findings.StatusError, "kyverno evaluation was cancelled or timed out"
				out = append(out, f)
				continue
			}
			out = append(out, e.evalOne(ctx, eng, p, n, r, objs[i], provider, user, ec)...)
		}
	}
	return out, nil
}

func (e *Engine) evalOne(ctx context.Context, eng vpolengine.Engine, p policy.Policy, n *native, r manifests.Resource, obj *unstructured.Unstructured, provider libs.Context, user authenticationv1.UserInfo, ec evalctx.Context) (out []findings.Finding) {
	one := func(st findings.Status, msg string) []findings.Finding {
		f := base(p, r)
		f.Status, f.Message = st, msg
		return []findings.Finding{f}
	}
	// A panic inside the upstream engine must surface as an error.
	defer func() {
		if rec := recover(); rec != nil {
			out = one(findings.StatusError, fmt.Sprintf("kyverno engine panicked: %v", rec))
		}
	}()

	namespace := obj.GetNamespace()
	clusterScoped := manifests.IsClusterScoped(obj.GetKind())
	if obj.GetKind() == "Namespace" {
		namespace = obj.GetName()
	}
	if n.namespace != "" && namespace != n.namespace {
		return one(findings.StatusNotApplicable, fmt.Sprintf("policy only applies in namespace %q", n.namespace))
	}
	nsKnown := ec.NamespaceLabelsKnown(namespace)
	if clusterScoped && obj.GetKind() != "Namespace" {
		nsKnown = true
	}
	missingNS := func() []findings.Finding {
		f := base(p, r)
		f.Status = findings.StatusUnknown
		f.MissingContext = []string{"namespace.labels"}
		if namespace == "" {
			f.Message = "cannot determine compliance: the policy depends on namespace metadata, but the resource has no namespace and no target namespace was given in the context"
		} else {
			f.Message = fmt.Sprintf("cannot determine compliance: the policy depends on the labels of namespace %q, which were not supplied in the context", namespace)
		}
		return []findings.Finding{f}
	}

	gvk := obj.GroupVersionKind()
	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	var object, oldObject runtime.Object
	operation := admissionv1.Create
	switch ec.Operation {
	case "UPDATE":
		operation, object, oldObject = admissionv1.Update, obj, obj.DeepCopy()
	case "DELETE":
		operation, oldObject = admissionv1.Delete, obj.DeepCopy()
	default:
		object = obj
	}
	request := celengine.Request(provider, gvk, gvr, "", obj.GetName(), namespace, operation, user, object, oldObject, false, nil)
	resp, err := eng.Handle(ctx, request, nil)
	if err != nil {
		return one(findings.StatusError, "kyverno evaluation failed: "+err.Error())
	}
	// Autogen adds copies of the policy for pod controllers. They share the
	// policy name, so all their rules belong to this policy.
	var rules []engineapi.RuleResponse
	for _, pr := range resp.Policies {
		rules = append(rules, pr.Rules...)
	}
	if len(rules) == 0 {
		if n.usesNamespaceSelector && !nsKnown {
			return missingNS()
		}
		return one(findings.StatusNotApplicable, "resource does not match the policy's match constraints for operation "+ec.Operation)
	}
	for _, rule := range rules {
		f := base(p, r)
		f.Rule = rule.Name()
		props := rule.Properties()
		if idx, ok := props[validationIndexKey]; ok {
			f.Rule = "validations[" + idx + "]"
		}
		f.Field = props["field"]
		if rem := props["remediation"]; rem != "" {
			f.Remediation = &findings.Remediation{Description: rem, Source: "rule-result"}
		}
		f.Message = rule.Message()
		exempt := func() {
			f.Status = findings.StatusExempted
			var names []string
			for _, ex := range rule.Exceptions() {
				names = append(names, ex.GetNamespace()+"/"+ex.GetName())
			}
			f.Exemption = &findings.Exemption{Name: strings.Join(names, ", "), Source: "kyverno-policy-exception"}
		}
		switch rule.Status() {
		case engineapi.RuleStatusPass:
			f.Status = findings.StatusPass
			f.Message = ""
			if rule.IsException() {
				exempt()
				f.Message = rule.Message()
			}
		case engineapi.RuleStatusFail:
			if p.Enforcement == policy.EnforceDeny {
				f.Status = findings.StatusFail
			} else {
				f.Status = findings.StatusWarning
			}
		case engineapi.RuleStatusWarn:
			f.Status = findings.StatusWarning
		case engineapi.RuleStatusSkip:
			if rule.IsException() {
				exempt()
			} else {
				f.Status = findings.StatusNotApplicable
				f.Rule = ""
				f.Message = "the policy's match conditions do not hold for this resource"
			}
		default: // error, or any status this adapter does not know
			f.Status = findings.StatusError
			f.Details = map[string]any{"engineStatus": string(rule.Status())}
			switch {
			case n.usesNamespaceObject && !nsKnown:
				return missingNS()
			case n.usesResourceLookup:
				f.Status = findings.StatusUnknown
				f.MissingContext = []string{"resources"}
				f.Message = "cannot determine compliance: the policy looks up other cluster resources (resource.Get or resource.List) and the lookup failed. Supply the needed resources in context.resources. Engine message: " + rule.Message()
			case n.usesGlobalContext:
				f.Status = findings.StatusUnknown
				f.MissingContext = []string{"data"}
				f.Message = "cannot determine compliance: the policy reads globalContext entries that were not supplied in context.data. Engine message: " + rule.Message()
			default:
				f.Message = "kyverno rule evaluation error: " + rule.Message()
			}
		}
		// A verdict computed from a null namespaceObject cannot be trusted.
		if n.usesNamespaceObject && !nsKnown && (f.Status == findings.StatusPass || f.Status == findings.StatusFail || f.Status == findings.StatusWarning) {
			return missingNS()
		}
		if f.Status == findings.StatusFail || f.Status == findings.StatusWarning {
			if f.Severity == "" {
				f.Severity = map[bool]string{true: "error", false: "warning"}[f.Status == findings.StatusFail]
			}
		}
		out = append(out, f)
	}
	return out
}

func base(p policy.Policy, r manifests.Resource) findings.Finding {
	return findings.Finding{Engine: EngineName, Policy: p.ID, Resource: r.Ref(), Severity: p.Severity, Enforcement: p.Enforcement}
}

func forAll(p policy.Policy, resources []manifests.Resource, st findings.Status, msg string) []findings.Finding {
	out := make([]findings.Finding, 0, len(resources))
	for _, r := range resources {
		f := base(p, r)
		f.Status, f.Message = st, msg
		out = append(out, f)
	}
	return out
}

// toUnstructured converts through JSON so the object only holds JSON types.
func toUnstructured(obj map[string]any) (*unstructured.Unstructured, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("resource is not JSON-serialisable: %w", err)
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(b); err != nil {
		return nil, err
	}
	return u, nil
}

func addToContext(p *libs.FakeContextProvider, u *unstructured.Unstructured) {
	gvr, _ := meta.UnsafeGuessKindToResource(u.GroupVersionKind())
	_ = p.AddResource(gvr, u)
}
