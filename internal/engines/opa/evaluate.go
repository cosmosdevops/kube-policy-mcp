package opa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// Evaluate implements policy.Engine.
//
// Each resource is passed as input, as Conftest does. The simulated context
// is available to policies under data.kubepolicy:
//
//	data.kubepolicy.context     kubernetesVersion, operation, user, variables, namespace
//	data.kubepolicy.namespaces  namespace metadata keyed by name
//	data.kubepolicy.resources   every submitted and context resource
//	data.kubepolicy.data        arbitrary caller-supplied policy data
func (e *Engine) Evaluate(ctx context.Context, resources []manifests.Resource, policies []policy.Policy, ec evalctx.Context) ([]findings.Finding, error) {
	ctxData, err := contextData(resources, ec)
	if err != nil {
		return nil, err
	}
	var out []findings.Finding
	stores := map[*unit]storage.Store{}
	for _, p := range policies {
		n, _ := p.Native.(*native)
		switch {
		case n == nil || n.unit == nil:
			out = append(out, forAll(p, resources, findings.StatusError, "policy was not loaded by the opa engine")...)
			continue
		case p.LoadError || n.unit.compileErr != nil || n.unit.compiler == nil:
			msg := p.Problem
			if msg == "" && n.unit.compileErr != nil {
				msg = n.unit.compileErr.Error()
			}
			out = append(out, forAll(p, resources, findings.StatusError, "policy could not be loaded: "+msg)...)
			continue
		}
		store, ok := stores[n.unit]
		if !ok {
			data := make(map[string]any, len(n.unit.data)+1)
			for k, v := range n.unit.data {
				data[k] = v
			}
			data[ReservedRoot] = ctxData
			store = inmem.NewFromObject(data)
			stores[n.unit] = store
		}
		queries := map[string]rego.PreparedEvalQuery{}
		var prepErr error
		for _, rn := range append([]string{ruleApplies}, resultRules...) {
			if !n.rules[rn] {
				continue
			}
			q, err := rego.New(
				rego.Compiler(n.unit.compiler),
				rego.Store(store),
				rego.Query(n.pkg+"."+rn),
				rego.StrictBuiltinErrors(true),
			).PrepareForEval(ctx)
			if err != nil {
				prepErr = err
				break
			}
			queries[rn] = q
		}
		if prepErr != nil {
			out = append(out, forAll(p, resources, findings.StatusError, "failed to prepare policy: "+prepErr.Error())...)
			continue
		}
		for _, r := range resources {
			out = append(out, e.evalOne(ctx, p, queries, r)...)
		}
	}
	return out, nil
}

func (e *Engine) evalOne(ctx context.Context, p policy.Policy, queries map[string]rego.PreparedEvalQuery, r manifests.Resource) []findings.Finding {
	base := findings.Finding{Engine: EngineName, Policy: p.ID, Resource: r.Ref(), Severity: p.Severity, Enforcement: p.Enforcement}
	fail := func(err error) []findings.Finding {
		f := base
		f.Status = findings.StatusError
		f.Message = "rego evaluation failed: " + err.Error()
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
			f.Message = "rego evaluation was cancelled or timed out"
		}
		return []findings.Finding{f}
	}
	if !p.AppliesToKind(r.Kind()) {
		f := base
		f.Status = findings.StatusNotApplicable
		f.Message = fmt.Sprintf("policy applies to kinds %s", strings.Join(p.Kinds, ", "))
		return []findings.Finding{f}
	}
	input := rego.EvalInput(r.Object)
	if q, ok := queries[ruleApplies]; ok {
		rs, err := q.Eval(ctx, input)
		if err != nil {
			return fail(err)
		}
		applies := len(rs) > 0 && len(rs[0].Expressions) > 0 && rs[0].Expressions[0].Value == true
		if !applies {
			f := base
			f.Status = findings.StatusNotApplicable
			f.Message = "the policy's applies rule does not hold for this resource"
			return []findings.Finding{f}
		}
	}
	var out []findings.Finding
	for _, rn := range resultRules {
		q, ok := queries[rn]
		if !ok {
			continue
		}
		rs, err := q.Eval(ctx, input)
		if err != nil {
			return fail(err)
		}
		if len(rs) == 0 || len(rs[0].Expressions) == 0 {
			continue
		}
		for _, item := range resultItems(rs[0].Expressions[0].Value, rn) {
			f := base
			f.Rule = rn
			switch rn {
			case ruleDeny, ruleViolation:
				f.Status, f.Enforcement = findings.StatusFail, policy.EnforceDeny
				if f.Severity == "" {
					f.Severity = "error"
				}
			case ruleWarn:
				f.Status, f.Enforcement = findings.StatusWarning, policy.EnforceWarn
				if f.Severity == "" {
					f.Severity = "warning"
				}
			case ruleUnknown:
				f.Status = findings.StatusUnknown
			}
			applyItem(&f, item)
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		f := base
		f.Status = findings.StatusPass
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Message < out[j].Message
	})
	return out
}

// resultItems normalises the value of a result rule into a list. Rules are
// normally sets of strings or objects; a bare true is accepted as well.
func resultItems(v any, rule string) []any {
	switch t := v.(type) {
	case []any:
		return t
	case map[string]any:
		// Partial object rule: report each value.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]any, 0, len(t))
		for _, k := range keys {
			out = append(out, t[k])
		}
		return out
	case bool:
		if t {
			return []any{fmt.Sprintf("rule %q is true", rule)}
		}
		return nil
	case string:
		return []any{t}
	case nil:
		return nil
	}
	return []any{v}
}

// applyItem copies a rule result into the finding. Object results may carry
// msg/message, field, id, remediation, severity and missingContext; anything
// else is kept under details.
func applyItem(f *findings.Finding, item any) {
	switch t := item.(type) {
	case string:
		f.Message = t
	case map[string]any:
		details := map[string]any{}
		for k, v := range t {
			s, isStr := v.(string)
			switch {
			case (k == "msg" || k == "message") && isStr:
				f.Message = s
			case k == "field" && isStr:
				f.Field = s
			case (k == "id" || k == "rule") && isStr:
				f.Rule = f.Rule + "/" + s
			case k == "remediation" && isStr:
				f.Remediation = &findings.Remediation{Description: s, Source: "rule-result"}
			case k == "severity" && isStr:
				f.Severity = s
			case k == "missingContext":
				f.MissingContext = stringList(v)
			default:
				details[k] = v
			}
		}
		if len(details) > 0 {
			f.Details = details
		}
		if f.Message == "" {
			b, _ := json.Marshal(t)
			f.Message = string(b)
		}
	default:
		f.Message = fmt.Sprint(item)
	}
}

func forAll(p policy.Policy, resources []manifests.Resource, st findings.Status, msg string) []findings.Finding {
	out := make([]findings.Finding, 0, len(resources))
	for _, r := range resources {
		out = append(out, findings.Finding{Engine: EngineName, Policy: p.ID, Resource: r.Ref(), Status: st, Severity: p.Severity, Enforcement: p.Enforcement, Message: msg})
	}
	return out
}

// contextData builds the document exposed at data.kubepolicy.
func contextData(resources []manifests.Resource, ec evalctx.Context) (map[string]any, error) {
	objs := make([]any, 0, len(resources)+len(ec.Resources))
	for _, r := range resources {
		objs = append(objs, r.Object)
	}
	for _, r := range ec.Resources {
		objs = append(objs, r)
	}
	namespaces := map[string]any{}
	for _, ns := range ec.AllNamespaces() {
		namespaces[ns.Name] = map[string]any{"name": ns.Name, "labels": orEmpty(ns.Labels), "annotations": orEmpty(ns.Annotations)}
	}
	c := map[string]any{
		"operation": ec.Operation,
		"variables": ec.Variables,
	}
	if ec.KubernetesVersion != "" {
		c["kubernetesVersion"] = ec.KubernetesVersion
	}
	if ec.Namespace != nil {
		c["namespace"] = ec.Namespace.Name
	}
	if ec.User != nil {
		c["user"] = map[string]any{"username": ec.User.Username, "uid": ec.User.UID, "groups": ec.User.Groups}
	}
	doc := map[string]any{"context": c, "namespaces": namespaces, "resources": objs, "data": ec.Data}
	// Round-trip through JSON so the store only holds plain JSON types.
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("evaluation context is not JSON-serialisable: %w", err)
	}
	var plain map[string]any
	if err := json.Unmarshal(b, &plain); err != nil {
		return nil, err
	}
	for _, k := range []string{"data"} {
		if plain[k] == nil {
			plain[k] = map[string]any{}
		}
	}
	if cm, ok := plain["context"].(map[string]any); ok && cm["variables"] == nil {
		cm["variables"] = map[string]any{}
	}
	return plain, nil
}

func orEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
