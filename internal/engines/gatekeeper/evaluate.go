package gatekeeper

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/reviews"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/controller/config/process"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/expansion"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/gator/expand"
	mutationtypes "github.com/open-policy-agent/gatekeeper/v3/pkg/mutation/types"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// exemptionSource marks findings exempted by a Gatekeeper Config resource.
const exemptionSource = "gatekeeper-config"

// Evaluate implements policy.Engine. Each source gets its own constraint
// client, because two sources may define the same constraint kind.
func (e *Engine) Evaluate(ctx context.Context, resources []manifests.Resource, policies []policy.Policy, ec evalctx.Context) ([]findings.Finding, error) {
	objs := make([]*unstructured.Unstructured, len(resources))
	for i, r := range resources {
		u, err := toUnstructured(r.Object)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Source, err)
		}
		objs[i] = u
	}
	// data holds everything templates can read through data.inventory.
	data := append([]*unstructured.Unstructured{}, objs...)
	for i, obj := range ec.Resources {
		u, err := toUnstructured(obj)
		if err != nil {
			return nil, fmt.Errorf("context.resources[%d]: %w", i, err)
		}
		if u.GetKind() == "" || u.GetAPIVersion() == "" {
			return nil, fmt.Errorf("context.resources[%d] has no apiVersion or kind", i)
		}
		data = append(data, u)
	}
	var namespaces []*unstructured.Unstructured
	for _, ns := range ec.AllNamespaces() {
		u, err := namespaceObject(ns)
		if err != nil {
			return nil, err
		}
		namespaces = append(namespaces, u)
	}

	var out []findings.Finding
	byUnit := map[*unit][]policy.Policy{}
	var units []*unit
	for _, p := range policies {
		n, _ := p.Native.(*native)
		switch {
		case n == nil || n.unit == nil:
			out = append(out, forAll(p, resources, findings.StatusError, "policy was not loaded by the gatekeeper engine")...)
		case p.LoadError:
			out = append(out, forAll(p, resources, findings.StatusError, "policy could not be loaded: "+p.Problem)...)
		case !p.Supported:
			// Unsupported checks are unknown for the kinds they may apply to.
			for _, r := range resources {
				f := base(p, r)
				if !p.AppliesToKind(r.Kind()) {
					f.Status, f.Message = findings.StatusNotApplicable, "resource kind is not matched by the constraint"
				} else {
					f.Status, f.Message = findings.StatusUnknown, "unsupported check: "+p.Problem
				}
				out = append(out, f)
			}
		default:
			if _, ok := byUnit[n.unit]; !ok {
				units = append(units, n.unit)
			}
			byUnit[n.unit] = append(byUnit[n.unit], p)
		}
	}
	for _, u := range units {
		out = append(out, evalUnit(ctx, u, byUnit[u], resources, objs, data, namespaces, ec)...)
	}
	return out, nil
}

// evalUnit evaluates the constraints of one source against every resource.
func evalUnit(ctx context.Context, u *unit, policies []policy.Policy, resources []manifests.Resource, objs, data, namespaces []*unstructured.Unstructured, ec evalctx.Context) (out []findings.Finding) {
	failAll := func(msg string) []findings.Finding {
		var fs []findings.Finding
		for _, p := range policies {
			fs = append(fs, forAll(p, resources, findings.StatusError, msg)...)
		}
		return fs
	}
	// A panic inside the upstream code must surface as an error.
	defer func() {
		if rec := recover(); rec != nil {
			out = failAll(fmt.Sprintf("gatekeeper evaluation panicked: %v", rec))
		}
	}()

	client, handler, err := newClient()
	if err != nil {
		return failAll(err.Error())
	}
	// Policies that fail to set up are reported as errors; the rest go on.
	setupErr := map[string]string{}
	added := map[string]bool{}
	for _, p := range policies {
		n := p.Native.(*native)
		if t := n.template; !added[t.kind] {
			added[t.kind] = true
			if _, err := client.AddTemplate(ctx, t.template.DeepCopy()); err != nil {
				setupErr[t.kind] = "ConstraintTemplate could not be added: " + err.Error()
			}
		}
		if msg, bad := setupErr[n.template.kind]; bad {
			setupErr[p.ID] = msg
			continue
		}
		if err := addConstraint(ctx, client, n.constraint); err != nil {
			setupErr[p.ID] = "constraint could not be added: " + err.Error()
		}
	}
	for _, obj := range append(append([]*unstructured.Unstructured{}, namespaces...), data...) {
		if _, err := client.AddData(ctx, obj.DeepCopy()); err != nil {
			return failAll(fmt.Sprintf("adding %s %s to the inventory failed: %v", obj.GetKind(), obj.GetName(), err))
		}
	}
	var expander *expand.Expander
	if u.hasExpansions {
		src := append(append([]*unstructured.Unstructured{}, u.expansion...), namespaces...)
		copies := make([]*unstructured.Unstructured, len(src))
		for i, o := range src {
			copies[i] = o.DeepCopy()
		}
		if expander, err = expand.NewExpander(copies); err != nil {
			return failAll("setting up expansion templates failed: " + err.Error())
		}
	}
	excluder := process.New()
	for _, cfg := range u.configs {
		excluder.Add(cfg.Spec.Match)
	}

	operation := admissionv1.Create
	switch ec.Operation {
	case "UPDATE":
		operation = admissionv1.Update
	case "DELETE":
		operation = admissionv1.Delete
	}

	for i, r := range resources {
		obj := objs[i]
		if err := ctx.Err(); err != nil {
			for _, p := range policies {
				f := base(p, r)
				f.Status, f.Message = findings.StatusError, "evaluation was cancelled or timed out"
				out = append(out, f)
			}
			continue
		}
		kind := obj.GetKind()
		namespace := obj.GetNamespace()
		// Cluster-scoped objects have no namespace to look up. A Namespace
		// is matched on its own labels, which are part of the object.
		nsKnown := true
		var nsObj *corev1.Namespace
		switch {
		case kind == "Namespace":
			namespace = obj.GetName()
		case manifests.IsClusterScoped(kind) || namespace == "":
			nsKnown = manifests.IsClusterScoped(kind)
			nsObj = &corev1.Namespace{}
		default:
			nsKnown = ec.NamespaceLabelsKnown(namespace)
			if ns, ok := ec.NamespaceFor(namespace); ok {
				nsObj = toNamespace(ns)
			}
		}

		if excluded, _ := excluder.IsNamespaceExcluded(process.Webhook, obj); excluded {
			for _, p := range policies {
				f := base(p, r)
				f.Status = findings.StatusExempted
				f.Message = fmt.Sprintf("namespace %q is excluded from Gatekeeper admission by a Config resource", namespace)
				f.Exemption = &findings.Exemption{Name: configNames(u), Source: exemptionSource, Reason: "spec.match.excludedNamespaces of the Gatekeeper Config"}
				out = append(out, f)
			}
			continue
		}

		// Review the resource, and what expansion templates generate from it.
		reviewed := []target.AugmentedUnstructured{{Object: *obj.DeepCopy(), Namespace: nsObj, Operation: operation, Source: mutationtypes.SourceTypeOriginal}}
		responses, reviewErr := client.Review(ctx, reviewed[0], reviews.EnforcementPoint(util.WebhookEnforcementPoint))
		if expander != nil && reviewErr == nil {
			resultants, err := expander.Expand(obj.DeepCopy())
			if err != nil {
				reviewErr = fmt.Errorf("expanding the resource failed: %w", err)
			}
			for _, res := range resultants {
				au := target.AugmentedUnstructured{Object: *res.Obj, Namespace: nsObj, Operation: operation, Source: mutationtypes.SourceTypeGenerated}
				child, err := client.Review(ctx, au, reviews.EnforcementPoint(util.WebhookEnforcementPoint))
				if err != nil {
					reviewErr = fmt.Errorf("reviewing the %s generated by %s failed: %w", res.Obj.GetKind(), res.TemplateName, err)
					break
				}
				expansion.OverrideEnforcementAction(res.EnforcementAction, child)
				expansion.AggregateResponses(res.TemplateName, responses, child)
				reviewed = append(reviewed, au)
			}
		}
		results := map[string][]*types.Result{}
		if reviewErr == nil && responses != nil {
			for _, resp := range responses.ByTarget {
				for _, res := range resp.Results {
					if res.Constraint != nil {
						key := res.Constraint.GetKind() + "/" + res.Constraint.GetName()
						results[key] = append(results[key], res)
					}
				}
			}
		}

		for _, p := range policies {
			n := p.Native.(*native)
			one := func(st findings.Status, msg string) {
				f := base(p, r)
				f.Status, f.Message = st, msg
				out = append(out, f)
			}
			if msg, bad := setupErr[p.ID]; bad {
				one(findings.StatusError, msg)
				continue
			}
			if !n.atAdmission {
				one(findings.StatusNotApplicable, "the constraint has no enforcement action for admission ("+util.WebhookEnforcementPoint+")")
				continue
			}
			if !templateHandles(n.template, operation) {
				one(findings.StatusNotApplicable, "the ConstraintTemplate does not handle operation "+ec.Operation)
				continue
			}
			// Does the constraint select the resource, leaving the namespace
			// selector aside? If not, missing namespace labels do not matter.
			matched, err := matches(handler, n.constraint, reviewed, true)
			if err != nil {
				one(findings.StatusError, "matching the constraint failed: "+err.Error())
				continue
			}
			if !matched {
				one(findings.StatusNotApplicable, "resource does not match the constraint's match criteria")
				continue
			}
			if n.usesNamespaceSelector {
				if !nsKnown {
					f := base(p, r)
					f.Status = findings.StatusUnknown
					f.MissingContext = []string{"namespace.labels"}
					if namespace == "" {
						f.Message = "cannot determine compliance: the constraint matches on namespace labels, but the resource has no namespace and no target namespace was given in the context"
					} else {
						f.Message = fmt.Sprintf("cannot determine compliance: the constraint matches on the labels of namespace %q, which were not supplied in the context", namespace)
					}
					out = append(out, f)
					continue
				}
				if matched, err = matches(handler, n.constraint, reviewed, false); err != nil {
					one(findings.StatusError, "matching the constraint failed: "+err.Error())
					continue
				} else if !matched {
					one(findings.StatusNotApplicable, "the namespace of the resource does not match the constraint's namespace selector")
					continue
				}
			}
			if reviewErr != nil {
				one(findings.StatusError, "gatekeeper review failed: "+reviewErr.Error())
				continue
			}
			rs := results[n.constraint.GetKind()+"/"+n.constraint.GetName()]
			if len(rs) == 0 {
				one(findings.StatusPass, "")
				continue
			}
			fs := make([]findings.Finding, 0, len(rs))
			for _, res := range rs {
				fs = append(fs, toFinding(p, r, res))
			}
			sort.SliceStable(fs, func(i, j int) bool { return fs[i].Message < fs[j].Message })
			out = append(out, fs...)
		}
	}
	return out
}

// toFinding maps one Gatekeeper violation to a finding. A violation's
// details may carry "field" and "remediation" strings, which are copied into
// the finding; the rest is kept under details.
func toFinding(p policy.Policy, r manifests.Resource, res *types.Result) findings.Finding {
	f := base(p, r)
	f.Rule = ruleViolation
	f.Message = res.Msg
	actions := []string{strings.ToLower(res.EnforcementAction)}
	if actions[0] == actionScoped {
		actions = nil
		for _, a := range res.ScopedEnforcementActions {
			actions = append(actions, strings.ToLower(a))
		}
	}
	switch {
	case slices.Contains(actions, actionDeny):
		f.Status, f.Enforcement = findings.StatusFail, policy.EnforceDeny
	case slices.Contains(actions, actionWarn):
		f.Status, f.Enforcement = findings.StatusWarning, policy.EnforceWarn
	case slices.Contains(actions, actionDryRun):
		f.Status, f.Enforcement = findings.StatusWarning, policy.EnforceAudit
	default:
		f.Status = findings.StatusError
		f.Message = fmt.Sprintf("violation with unknown enforcement action %q: %s", res.EnforcementAction, res.Msg)
		return f
	}
	if f.Severity == "" {
		f.Severity = map[bool]string{true: "error", false: "warning"}[f.Status == findings.StatusFail]
	}
	details := map[string]any{}
	if d, ok := res.Metadata["details"].(map[string]any); ok {
		for k, v := range d {
			s, isStr := v.(string)
			switch {
			case k == "field" && isStr:
				f.Field = s
			case k == "remediation" && isStr:
				f.Remediation = &findings.Remediation{Description: s, Source: "rule-result"}
			default:
				details[k] = v
			}
		}
	} else if d, ok := res.Metadata["details"]; ok && d != nil {
		details["details"] = d
	}
	if len(details) > 0 {
		f.Details = details
	}
	return f
}

// matches runs the upstream constraint matcher against the resource and the
// resources generated from it. With ignoreNamespaceSelector the namespace
// selector is left out.
func matches(handler *target.K8sValidationTarget, constraint *unstructured.Unstructured, reviewed []target.AugmentedUnstructured, ignoreNamespaceSelector bool) (bool, error) {
	c := constraint
	if ignoreNamespaceSelector {
		c = constraint.DeepCopy()
		unstructured.RemoveNestedField(c.Object, "spec", "match", "namespaceSelector")
	}
	m, err := handler.ToMatcher(c)
	if err != nil {
		return false, err
	}
	for _, au := range reviewed {
		if ignoreNamespaceSelector && au.Namespace == nil {
			// Other namespace-based criteria still need a namespace object.
			au.Namespace = &corev1.Namespace{}
			au.Namespace.Name = au.Object.GetNamespace()
		}
		_, review, err := handler.HandleReview(au)
		if err != nil {
			return false, err
		}
		ok, err := m.Match(review)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// templateHandles reports whether a template takes part in an operation. A
// template that lists no operations handles all of them.
func templateHandles(t *loadedTemplate, op admissionv1.Operation) bool {
	if t.template == nil {
		return true
	}
	for _, tgt := range t.template.Spec.Targets {
		if len(tgt.Operations) == 0 {
			return true
		}
		for _, o := range tgt.Operations {
			if string(o) == "*" || strings.EqualFold(string(o), string(op)) {
				return true
			}
		}
	}
	return len(t.template.Spec.Targets) == 0
}

func configNames(u *unit) string {
	var names []string
	for _, cfg := range u.configs {
		name := cfg.Name
		if cfg.Namespace != "" {
			name = cfg.Namespace + "/" + name
		}
		names = append(names, "Config/"+name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
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

func namespaceObject(ns evalctx.Namespace) (*unstructured.Unstructured, error) {
	typed := toNamespace(ns)
	md := map[string]any{"name": typed.Name, "labels": typed.Labels}
	if len(typed.Annotations) > 0 {
		md["annotations"] = typed.Annotations
	}
	return toUnstructured(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": md})
}
