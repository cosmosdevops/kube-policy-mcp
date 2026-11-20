package vap

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/policy/generic"
	"k8s.io/apiserver/pkg/admission/plugin/policy/matching"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// Audit annotation keys the adapter copies into findings. The plain key is
// used when exactly one validation failed; "<key>.<index>" always belongs to
// the validation with that index.
const (
	hintField       = "field"
	hintRemediation = "remediation"
)

// run holds what is shared by one Evaluate call.
type run struct {
	ec      evalctx.Context
	matcher generic.PolicyMatcher
	oi      admission.ObjectInterfaces
	user    user.Info
	// extra are the objects, besides a source's own, that a paramRef may
	// name: the submitted manifests and context.resources.
	extra []*unstructured.Unstructured
}

// Evaluate implements policy.Engine. It builds a simulated admission request
// for each resource and runs it through the upstream policy validator, once
// for every binding of the policy that selects the resource.
func (e *Engine) Evaluate(ctx context.Context, resources []manifests.Resource, policies []policy.Policy, ec evalctx.Context) ([]findings.Finding, error) {
	rn := &run{
		ec:      ec,
		matcher: generic.NewPolicyMatcher(matching.NewMatcher(namespaceLister{ec: &ec}, nil)),
		oi:      admission.NewObjectInterfacesFromScheme(runtime.NewScheme()),
		user:    &user.DefaultInfo{},
	}
	if ec.User != nil {
		rn.user = &user.DefaultInfo{Name: ec.User.Username, UID: ec.User.UID, Groups: ec.User.Groups}
	}
	objs := make([]*unstructured.Unstructured, len(resources))
	for i, r := range resources {
		u, err := toUnstructured(r.Object)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Source, err)
		}
		objs[i] = u
		rn.extra = append(rn.extra, u)
	}
	for i, obj := range ec.Resources {
		u, err := toUnstructured(obj)
		if err != nil {
			return nil, fmt.Errorf("context.resources[%d]: %w", i, err)
		}
		if u.GetKind() == "" || u.GetAPIVersion() == "" {
			return nil, fmt.Errorf("context.resources[%d] has no apiVersion or kind", i)
		}
		rn.extra = append(rn.extra, u)
	}

	var out []findings.Finding
	for _, p := range policies {
		n, _ := p.Native.(*native)
		switch {
		case n == nil:
			out = append(out, forAll(p, resources, findings.StatusError, "policy was not loaded by the vap engine")...)
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
		for i, r := range resources {
			if err := ctx.Err(); err != nil {
				f := base(p, r)
				f.Status, f.Message = findings.StatusError, "evaluation was cancelled or timed out"
				out = append(out, f)
				continue
			}
			out = append(out, rn.evalOne(ctx, p, n, r, objs[i])...)
		}
	}
	return out, nil
}

func (rn *run) evalOne(ctx context.Context, p policy.Policy, n *native, r manifests.Resource, obj *unstructured.Unstructured) (out []findings.Finding) {
	one := func(st findings.Status, msg string) []findings.Finding {
		f := base(p, r)
		f.Status, f.Message = st, msg
		return []findings.Finding{f}
	}
	// A panic inside the upstream code must surface as an error.
	defer func() {
		if rec := recover(); rec != nil {
			out = one(findings.StatusError, fmt.Sprintf("admission policy evaluation panicked: %v", rec))
		}
	}()

	kind := obj.GetKind()
	namespace := obj.GetNamespace()
	// Cluster-scoped objects have no namespace to look up. A Namespace is
	// matched on its own labels, which are part of the object.
	nsKnown := true
	switch {
	case kind == "Namespace":
		namespace = obj.GetName()
	case manifests.IsClusterScoped(kind):
		namespace = ""
	default:
		nsKnown = rn.ec.NamespaceLabelsKnown(namespace)
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
	operation := admission.Create
	switch rn.ec.Operation {
	case "UPDATE":
		operation, object, oldObject = admission.Update, obj, obj.DeepCopy()
	case "DELETE":
		operation, oldObject = admission.Delete, obj.DeepCopy()
	default:
		object = obj
	}
	attr := admission.NewAttributesRecord(object, oldObject, gvk, namespace, obj.GetName(), gvr, "", operation, nil, false, rn.user)

	// Policy match. The namespace selector is checked last so that a
	// resource the policy would not select anyway is not reported as unknown.
	matched, matchResource, matchKind, err := rn.matchPolicy(attr, n.policy, true)
	if err != nil {
		return one(findings.StatusError, "matching the policy failed: "+err.Error())
	}
	if !matched {
		return one(findings.StatusNotApplicable, "resource does not match the policy's match constraints for operation "+rn.ec.Operation)
	}
	if hasNamespaceSelector(n.policy.Spec.MatchConstraints) {
		if !nsKnown {
			return missingNS()
		}
		if matched, matchResource, matchKind, err = rn.matchPolicy(attr, n.policy, false); err != nil {
			return one(findings.StatusError, "matching the policy failed: "+err.Error())
		} else if !matched {
			return one(findings.StatusNotApplicable, "the namespace of the resource does not match the policy's namespace selector")
		}
	}
	if n.usesNamespaceObject && !nsKnown {
		return missingNS()
	}

	var nsObj *corev1.Namespace
	if kind != "Namespace" && namespace != "" {
		if ns, ok := rn.ec.NamespaceFor(namespace); ok {
			nsObj = toNamespace(ns)
		}
	}
	versioned := &admission.VersionedAttributes{Attributes: attr, VersionedObject: object, VersionedOldObject: oldObject, VersionedKind: matchKind}

	var problems []findings.Finding
	seen := map[string]bool{}
	add := func(f findings.Finding) {
		key := strings.Join([]string{string(f.Status), f.Rule, f.Message, f.Field}, "\x00")
		if !seen[key] {
			seen[key] = true
			problems = append(problems, f)
		}
	}
	passes, bound := 0, 0
	for _, b := range n.bindings {
		detail := map[string]any{"binding": b.Name}
		note := func(st findings.Status, msg string) findings.Finding {
			f := base(p, r)
			f.Status, f.Message, f.Details = st, msg, detail
			f.Enforcement = bindingEnforcement(b)
			return f
		}
		ok, err := rn.matchBinding(attr, b, true)
		if err != nil {
			add(note(findings.StatusError, fmt.Sprintf("matching binding %s failed: %v", b.Name, err)))
			continue
		}
		if !ok {
			continue
		}
		if hasNamespaceSelector(b.Spec.MatchResources) {
			if !nsKnown {
				for _, f := range missingNS() {
					f.Details = detail
					add(f)
				}
				continue
			}
			if ok, err = rn.matchBinding(attr, b, false); err != nil {
				add(note(findings.StatusError, fmt.Sprintf("matching binding %s failed: %v", b.Name, err)))
				continue
			} else if !ok {
				continue
			}
		}
		bound++

		params, problem := rn.params(n, b, namespace)
		if problem != nil {
			f := note(problem.status, problem.message)
			f.MissingContext = problem.missing
			add(f)
			continue
		}
		for _, param := range params {
			var versionedParam runtime.Object
			paramDetail := detail
			if param != nil {
				versionedParam = param
				paramDetail = map[string]any{"binding": b.Name, "param": paramName(param)}
			}
			res := n.validator.Validate(ctx, matchResource, versioned, versionedParam, nsObj, celconfig.RuntimeCELCostBudget, nil)
			fs, passed := rn.decisions(p, r, n, b, res)
			for _, f := range fs {
				f.Details = paramDetail
				add(f)
			}
			if passed {
				passes++
			}
		}
	}
	switch {
	case len(problems) > 0:
		sort.SliceStable(problems, func(i, j int) bool {
			if problems[i].Rule != problems[j].Rule {
				return problems[i].Rule < problems[j].Rule
			}
			return problems[i].Message < problems[j].Message
		})
		return problems
	case passes > 0:
		return one(findings.StatusPass, "")
	case bound > 0:
		return one(findings.StatusNotApplicable, "the policy's match conditions do not hold for this resource")
	}
	return one(findings.StatusNotApplicable, "no binding of the policy selects this resource")
}

// decisions maps one upstream validation result to findings. passed is true
// when every validation admitted the resource.
func (rn *run) decisions(p policy.Policy, r manifests.Resource, n *native, b *admissionregistrationv1.ValidatingAdmissionPolicyBinding, res validating.ValidateResult) (out []findings.Finding, passed bool) {
	validations := n.policy.Spec.Validations
	enf := bindingEnforcement(b)
	newFinding := func() findings.Finding {
		f := base(p, r)
		f.Enforcement = enf
		return f
	}
	hints := map[string]string{}
	for _, a := range res.AuditAnnotations {
		switch a.Action {
		case validating.AuditAnnotationActionPublish:
			hints[a.Key] = a.Value
		case validating.AuditAnnotationActionError:
			f := newFinding()
			f.Status = findings.StatusError
			f.Message = fmt.Sprintf("audit annotation %q could not be evaluated: %s", a.Key, a.Error)
			out = append(out, f)
		}
	}
	// A result with no decisions means the match conditions did not hold.
	if len(res.Decisions) == 0 {
		return out, len(validations) == 0 && len(out) == 0
	}
	indexed := len(res.Decisions) == len(validations)
	denied := 0
	for _, d := range res.Decisions {
		if d.Evaluation == validating.EvalDeny {
			denied++
		}
	}
	for i, d := range res.Decisions {
		f := newFinding()
		if indexed {
			f.Rule = ruleID(i)
		}
		switch d.Evaluation {
		case validating.EvalAdmit:
			continue
		case validating.EvalDeny:
			f.Message = d.Message
			if enf == policy.EnforceDeny {
				f.Status = findings.StatusFail
			} else {
				f.Status = findings.StatusWarning
			}
			if f.Severity == "" {
				f.Severity = map[bool]string{true: "error", false: "warning"}[f.Status == findings.StatusFail]
			}
			idx := "." + strconv.Itoa(i)
			f.Field = hints[hintField+idx]
			rem := hints[hintRemediation+idx]
			if denied == 1 {
				if f.Field == "" {
					f.Field = hints[hintField]
				}
				if rem == "" {
					rem = hints[hintRemediation]
				}
			}
			if rem != "" {
				f.Remediation = &findings.Remediation{Description: rem, Source: "rule-result"}
			}
		default:
			// An evaluation error is never a pass, whatever the policy's
			// failurePolicy says: with failurePolicy Ignore the cluster
			// would admit the request without having checked it.
			f.Status = findings.StatusError
			f.Message = "CEL evaluation error: " + d.Message
		}
		out = append(out, f)
	}
	return out, len(out) == 0
}

// matchPolicy runs the upstream matcher for the policy's match constraints.
// With ignoreNamespaceSelector the namespace selector is left out.
func (rn *run) matchPolicy(attr admission.Attributes, p *admissionregistrationv1.ValidatingAdmissionPolicy, ignoreNamespaceSelector bool) (bool, schema.GroupVersionResource, schema.GroupVersionKind, error) {
	if ignoreNamespaceSelector {
		cp := *p
		m := *p.Spec.MatchConstraints
		m.NamespaceSelector = &metav1.LabelSelector{}
		cp.Spec.MatchConstraints = &m
		p = &cp
	}
	return rn.matcher.DefinitionMatches(attr, rn.oi, validating.NewValidatingAdmissionPolicyAccessor(p))
}

func (rn *run) matchBinding(attr admission.Attributes, b *admissionregistrationv1.ValidatingAdmissionPolicyBinding, ignoreNamespaceSelector bool) (bool, error) {
	if b.Spec.MatchResources == nil {
		return true, nil
	}
	if ignoreNamespaceSelector {
		cp := *b
		m := *b.Spec.MatchResources
		m.NamespaceSelector = &metav1.LabelSelector{}
		cp.Spec.MatchResources = &m
		b = &cp
	}
	return rn.matcher.BindingMatches(attr, rn.oi, validating.NewValidatingAdmissionPolicyBindingAccessor(b))
}

type paramProblem struct {
	status  findings.Status
	message string
	missing []string
}

// params finds the parameter objects a binding passes to the policy. The
// result holds a single nil when the policy takes no parameter.
//
// A parameter that cannot be found is always reported as unknown. In a
// cluster parameterNotFoundAction decides between allow and deny, but
// offline "not found" only means "not supplied".
func (rn *run) params(n *native, b *admissionregistrationv1.ValidatingAdmissionPolicyBinding, namespace string) ([]*unstructured.Unstructured, *paramProblem) {
	paramKind, ref := n.policy.Spec.ParamKind, b.Spec.ParamRef
	if paramKind == nil || ref == nil {
		return []*unstructured.Unstructured{nil}, nil
	}
	clusterScoped := manifests.IsClusterScoped(paramKind.Kind)
	paramNS := ""
	switch {
	case clusterScoped && ref.Namespace != "":
		return nil, &paramProblem{status: findings.StatusError, message: fmt.Sprintf("binding %s: paramRef.namespace must not be set for the cluster-scoped kind %s", b.Name, paramKind.Kind)}
	case clusterScoped:
	case ref.Namespace != "":
		paramNS = ref.Namespace
	case namespace != "":
		paramNS = namespace
	default:
		return nil, &paramProblem{status: findings.StatusError, message: fmt.Sprintf("binding %s: a namespaced paramRef without a namespace cannot be used for a cluster-scoped resource", b.Name)}
	}
	var selector labels.Selector
	if ref.Selector != nil {
		s, err := metav1.LabelSelectorAsSelector(ref.Selector)
		if err != nil {
			return nil, &paramProblem{status: findings.StatusError, message: fmt.Sprintf("binding %s: invalid paramRef.selector: %v", b.Name, err)}
		}
		selector = s
	}
	var found []*unstructured.Unstructured
	seen := map[string]bool{}
	for _, list := range [][]*unstructured.Unstructured{rn.extra, n.unit.params} {
		for _, obj := range list {
			if obj.GetAPIVersion() != paramKind.APIVersion || obj.GetKind() != paramKind.Kind {
				continue
			}
			if !clusterScoped && obj.GetNamespace() != paramNS {
				continue
			}
			if selector != nil && !selector.Matches(labels.Set(obj.GetLabels())) {
				continue
			}
			if selector == nil && obj.GetName() != ref.Name {
				continue
			}
			// The caller's objects come first and win over the source's.
			if key := paramName(obj); !seen[key] {
				seen[key] = true
				found = append(found, obj)
			}
		}
	}
	if len(found) == 0 {
		what := fmt.Sprintf("%s %q", paramKind.Kind, ref.Name)
		if selector != nil {
			what = fmt.Sprintf("a %s matching the selector %s", paramKind.Kind, selector)
		}
		if paramNS != "" {
			what += " in namespace " + paramNS
		}
		return nil, &paramProblem{
			status:  findings.StatusUnknown,
			missing: []string{"resources"},
			message: fmt.Sprintf("cannot determine compliance: binding %s passes %s to the policy as its parameter, and it was not found. Supply it in context.resources or put it in the policy source", b.Name, what),
		}
	}
	sort.Slice(found, func(i, j int) bool { return paramName(found[i]) < paramName(found[j]) })
	return found, nil
}

func paramName(u *unstructured.Unstructured) string {
	if u.GetNamespace() != "" {
		return u.GetNamespace() + "/" + u.GetName()
	}
	return u.GetName()
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

func toNamespace(ns evalctx.Namespace) *corev1.Namespace {
	out := &corev1.Namespace{}
	out.Name = ns.Name
	out.Labels = map[string]string{"kubernetes.io/metadata.name": ns.Name}
	for k, v := range ns.Labels {
		out.Labels[k] = v
	}
	out.Annotations = ns.Annotations
	return out
}

// namespaceLister serves namespace lookups from the evaluation context. It
// never reaches a cluster.
type namespaceLister struct{ ec *evalctx.Context }

func (l namespaceLister) List(selector labels.Selector) ([]*corev1.Namespace, error) {
	var out []*corev1.Namespace
	for _, ns := range l.ec.AllNamespaces() {
		if obj := toNamespace(ns); selector.Matches(labels.Set(obj.Labels)) {
			out = append(out, obj)
		}
	}
	return out, nil
}

func (l namespaceLister) Get(name string) (*corev1.Namespace, error) {
	ns, ok := l.ec.NamespaceFor(name)
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, name)
	}
	return toNamespace(ns), nil
}
