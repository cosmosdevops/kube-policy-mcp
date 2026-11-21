// Package evaluator is the MCP-independent core: it resolves a policy pack,
// runs each engine, and normalises the results into one report.
package evaluator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/packs"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
	"github.com/cosmosdevops/kube-policy-mcp/internal/remediation"
)

const maxMessageLen = 2000

// Evaluator evaluates resources against policy packs.
type Evaluator struct {
	Registry *packs.Registry
	Timeout  time.Duration
	// Now is replaceable for tests.
	Now func() time.Time
}

// Request is one evaluation request.
type Request struct {
	Resources []manifests.Resource
	Pack      string
	// Select optionally restricts evaluation to some policies of the pack.
	Select  Selection
	Context evalctx.Context
	// IncludeAll also lists pass and not_applicable results in the report.
	IncludeAll   bool
	SkippedFiles []findings.SkippedFile
}

// Result is a report plus what is needed to explain its findings later.
type Result struct {
	Report *findings.Report
	// All holds every finding, including pass and not_applicable.
	All       []findings.Finding
	Resources []manifests.Resource
	Policies  map[string]policy.Policy
	Redactor  *manifests.Redactor
}

// Evaluate runs the request. It returns an error only when the request
// itself is unusable; engine failures become error findings in the report.
func (e *Evaluator) Evaluate(ctx context.Context, req Request) (*Result, error) {
	if len(req.Resources) == 0 {
		return nil, errors.New("no Kubernetes resources to evaluate")
	}
	packName := req.Pack
	if packName == "" {
		packName = e.Registry.DefaultPack()
		if packName == "" {
			return nil, errors.New("no policy pack given and no default pack is configured")
		}
	}
	ec := req.Context
	if err := ec.Normalize(); err != nil {
		return nil, err
	}
	pack, err := e.Registry.Resolve(ctx, packName)
	if err != nil {
		return nil, err
	}
	if len(pack.Policies) == 0 {
		return nil, fmt.Errorf("policy pack %q contains no policies, so nothing can be concluded", packName)
	}
	policies, err := selectPolicies(pack.Policies, req.Select)
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return nil, fmt.Errorf("policy pack %q contains no policies, so nothing can be concluded", packName)
	}

	notes := append([]string(nil), pack.Notes...)
	// A partial evaluation must say so: its verdict only covers what was
	// selected, not the whole pack.
	if !req.Select.empty() && len(policies) < len(pack.Policies) {
		notes = append(notes, fmt.Sprintf("Only %d of the %d policies in the pack were evaluated (selected by %s). The verdict covers those policies only, not the whole pack.", len(policies), len(pack.Policies), req.Select.describe()))
	}
	notes = append(notes, "Context values (namespace, user, operation, variables) are simulated by the caller and are not verified against a cluster.")

	// Resources without a namespace are treated as deployed to the target namespace.
	resources := req.Resources
	if ec.Namespace != nil {
		var changed int
		resources, changed = manifests.ApplyDefaultNamespace(resources, ec.Namespace.Name)
		if changed > 0 {
			notes = append(notes, fmt.Sprintf("%d resource(s) without a namespace were evaluated as if deployed to namespace %q.", changed, ec.Namespace.Name))
		}
	}
	// Namespace objects in the request or context describe their namespaces.
	addNamespace := func(obj map[string]any) {
		r := manifests.Resource{Object: obj}
		if r.Kind() != "Namespace" || r.APIVersion() != "v1" || r.Name() == "" {
			return
		}
		md, _ := obj["metadata"].(map[string]any)
		labels := stringMap(md["labels"])
		if labels == nil {
			labels = map[string]string{} // a Namespace object states its labels fully
		}
		ec.AddNamespace(evalctx.Namespace{Name: r.Name(), Labels: labels, Annotations: stringMap(md["annotations"])})
	}
	for _, r := range resources {
		addNamespace(r.Object)
	}
	for _, obj := range ec.Resources {
		addNamespace(obj)
	}

	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	byEngine := map[string][]policy.Policy{}
	polByID := map[string]policy.Policy{}
	for _, p := range policies {
		byEngine[p.Engine] = append(byEngine[p.Engine], p)
		polByID[p.ID] = p
	}
	engineNames := make([]string, 0, len(byEngine))
	for n := range byEngine {
		engineNames = append(engineNames, n)
	}
	sort.Strings(engineNames)

	var all []findings.Finding
	for _, name := range engineNames {
		all = append(all, e.runEngine(ctx, name, byEngine[name], resources, ec, timeout)...)
	}

	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	exemptions, exNotes := activeExemptions(pack.Exemptions, now())
	notes = append(notes, exNotes...)

	all = enforceRequiredContext(all, polByID, resources, &ec)
	red := manifests.NewRedactor(resources, contextResources(ec))
	resIndex := map[string]int{}
	resByKey := map[string]manifests.Resource{}
	for i, r := range resources {
		resIndex[r.Ref().Key()] = i
		resByKey[r.Ref().Key()] = r
	}
	for i := range all {
		f := &all[i]
		p := polByID[f.Policy]
		applyExemptions(f, resByKey[f.Resource.Key()], exemptions)
		remediation.Attach(f, p)
		f.Message = red.Clean(f.Message, maxMessageLen)
		if f.Remediation != nil {
			f.Remediation.Description = red.Clean(f.Remediation.Description, maxMessageLen)
		}
		if f.Details != nil {
			f.Details, _ = red.CleanValue(f.Details, maxMessageLen).(map[string]any)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if ai, bi := resIndex[a.Resource.Key()], resIndex[b.Resource.Key()]; ai != bi {
			return ai < bi
		}
		if a.Policy != b.Policy {
			return a.Policy < b.Policy
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Message < b.Message
	})

	evalID := newID()
	report := &findings.Report{EvaluationID: evalID, PolicyPack: packName, SkippedFiles: req.SkippedFiles, Notes: notes, Findings: []findings.Finding{}}
	report.Summary.ResourcesEvaluated = len(resources)
	report.Summary.PoliciesEvaluated = len(policies)
	for _, r := range resources {
		report.Resources = append(report.Resources, r.Ref())
	}
	perPolicy := map[string]map[findings.Status]int{}
	for i := range all {
		all[i].ID = fmt.Sprintf("f-%s-%03d", evalID, i+1)
		f := all[i]
		if perPolicy[f.Policy] == nil {
			perPolicy[f.Policy] = map[findings.Status]int{}
		}
		perPolicy[f.Policy][f.Status]++
		if req.IncludeAll || f.Status.Actionable() {
			report.Findings = append(report.Findings, f)
		}
	}
	for _, p := range policies {
		report.PolicyResults = append(report.PolicyResults, findings.PolicyResult{
			Policy: p.ID, Engine: p.Engine, Title: p.Title, Severity: p.Severity, Enforcement: p.Enforcement, Results: perPolicy[p.ID],
		})
	}
	findings.Aggregate(report, all)
	if len(req.SkippedFiles) > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf("%d file(s) were skipped because they are not Kubernetes manifests; see skippedFiles.", len(req.SkippedFiles)))
	}
	return &Result{Report: report, All: all, Resources: resources, Policies: polByID, Redactor: red}, nil
}

// runEngine runs one engine with a timeout and guarantees a finding for
// every (policy, resource) pair. A failure, timeout, panic or missing result
// becomes an error finding, never a pass.
func (e *Evaluator) runEngine(ctx context.Context, name string, policies []policy.Policy, resources []manifests.Resource, ec evalctx.Context, timeout time.Duration) []findings.Finding {
	failAll := func(msg string) []findings.Finding {
		var out []findings.Finding
		for _, p := range policies {
			for _, r := range resources {
				out = append(out, findings.Finding{Engine: name, Policy: p.ID, Resource: r.Ref(), Status: findings.StatusError, Severity: p.Severity, Enforcement: p.Enforcement, Message: msg})
			}
		}
		return out
	}
	eng, ok := e.Registry.Engine(name)
	if !ok {
		return failAll(fmt.Sprintf("engine %q is not available", name))
	}
	ectx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		fs  []findings.Finding
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{err: fmt.Errorf("engine panicked: %v", r)}
			}
		}()
		fs, err := eng.Evaluate(ectx, resources, policies, ec)
		ch <- result{fs, err}
	}()
	var res result
	select {
	case res = <-ch:
	case <-ectx.Done():
		if errors.Is(ectx.Err(), context.DeadlineExceeded) {
			return failAll(fmt.Sprintf("%s evaluation timed out after %s", name, timeout))
		}
		return failAll(fmt.Sprintf("%s evaluation was cancelled", name))
	}
	if res.err != nil {
		return failAll(fmt.Sprintf("%s evaluation failed: %v", name, res.err))
	}
	known := map[string]bool{}
	for _, p := range policies {
		known[p.ID] = true
	}
	covered := map[string]bool{}
	var out []findings.Finding
	for _, f := range res.fs {
		if !known[f.Policy] {
			continue
		}
		if !validStatus(f.Status) {
			f.Message = fmt.Sprintf("engine returned unrecognised status %q: %s", f.Status, f.Message)
			f.Status = findings.StatusError
		}
		f.Engine = name
		covered[f.Policy+"\x00"+f.Resource.Key()] = true
		out = append(out, f)
	}
	for _, p := range policies {
		for _, r := range resources {
			if !covered[p.ID+"\x00"+r.Ref().Key()] {
				out = append(out, findings.Finding{Engine: name, Policy: p.ID, Resource: r.Ref(), Status: findings.StatusError, Severity: p.Severity, Enforcement: p.Enforcement, Message: "the engine returned no result for this policy and resource"})
			}
		}
	}
	return out
}

func validStatus(s findings.Status) bool {
	for _, k := range findings.AllStatuses {
		if k == s {
			return true
		}
	}
	return false
}

// enforceRequiredContext replaces verdicts that were computed without the
// context a policy declares it needs with a single unknown finding.
func enforceRequiredContext(all []findings.Finding, pols map[string]policy.Policy, resources []manifests.Resource, ec *evalctx.Context) []findings.Finding {
	type key struct{ pol, res string }
	missing := map[key][]string{}
	for _, f := range all {
		p := pols[f.Policy]
		if len(p.RequiredContext) == 0 {
			continue
		}
		switch f.Status {
		case findings.StatusPass, findings.StatusFail, findings.StatusWarning:
		case findings.StatusNotApplicable:
			// A "does not apply" verdict may itself rest on the missing
			// context (for example a namespace label check), unless the
			// resource kind is simply outside the policy's declared kinds.
			if !p.AppliesToKind(f.Resource.Kind) {
				continue
			}
		default:
			continue
		}
		required := p.RequiredContext
		if manifests.IsClusterScoped(f.Resource.Kind) && f.Resource.Kind != "Namespace" {
			required = nil
			for _, k := range p.RequiredContext {
				if !strings.HasPrefix(k, "namespace") {
					required = append(required, k)
				}
			}
		}
		ns := f.Resource.Namespace
		if f.Resource.Kind == "Namespace" {
			ns = f.Resource.Name
		}
		if m := ec.Missing(required, ns); len(m) > 0 {
			missing[key{f.Policy, f.Resource.Key()}] = m
		}
	}
	if len(missing) == 0 {
		return all
	}
	var out []findings.Finding
	done := map[key]bool{}
	for _, f := range all {
		k := key{f.Policy, f.Resource.Key()}
		m, hit := missing[k]
		if !hit {
			out = append(out, f)
			continue
		}
		if done[k] {
			continue
		}
		done[k] = true
		out = append(out, findings.Finding{
			Engine: f.Engine, Policy: f.Policy, Resource: f.Resource, Status: findings.StatusUnknown,
			Severity: f.Severity, Enforcement: f.Enforcement, MissingContext: m,
			Message: "cannot determine compliance: the policy needs context that was not supplied: " + strings.Join(m, ", "),
		})
	}
	return out
}

func activeExemptions(in []packs.Exemption, now time.Time) (active []packs.Exemption, notes []string) {
	for _, e := range in {
		if e.Expires != "" {
			if t, err := time.Parse("2006-01-02", e.Expires); err == nil && now.After(t.Add(24*time.Hour)) {
				notes = append(notes, fmt.Sprintf("Exemption %q (pack %s) expired on %s and was ignored.", e.Name, e.Pack, e.Expires))
				continue
			}
		}
		active = append(active, e)
	}
	return active, notes
}

// applyExemptions turns a fail or warning into exempted when a pack-level
// exemption covers the policy and resource. Unknown and error results are
// left alone: an exemption does not make an incomplete check complete.
func applyExemptions(f *findings.Finding, r manifests.Resource, exemptions []packs.Exemption) {
	if f.Status != findings.StatusFail && f.Status != findings.StatusWarning {
		return
	}
	for _, e := range exemptions {
		if !matchAny(e.Policies, f.Policy) {
			continue
		}
		sel := e.Resource
		if len(sel.Kinds) > 0 && !matchAny(sel.Kinds, f.Resource.Kind) {
			continue
		}
		if len(sel.Namespaces) > 0 && !matchAny(sel.Namespaces, f.Resource.Namespace) {
			continue
		}
		if len(sel.Names) > 0 && !matchAny(sel.Names, r.Name()) {
			continue
		}
		f.Status = findings.StatusExempted
		f.Exemption = &findings.Exemption{Name: e.Name, Reason: e.Reason, Source: "pack-exemption"}
		return
	}
}

func matchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if p == s {
			return true
		}
		if strings.Contains(p, "*") {
			re := "^" + strings.ReplaceAll(regexp.QuoteMeta(p), `\*`, ".*") + "$"
			if ok, _ := regexp.MatchString(re, s); ok {
				return true
			}
		}
	}
	return false
}

// Selection narrows an evaluation to some policies of a pack. The three
// parts are combined: a policy must satisfy every part that is set. An empty
// Selection means the whole pack.
type Selection struct {
	// IDs holds policy ids. An entry may use * as a wildcard, for example
	// "vap/*" or "*host*". A bare policy name is accepted when it is unique.
	IDs []string
	// Engines keeps policies of these engines.
	Engines []string
	// Severities keeps policies with one of these severities.
	Severities []string
}

func (s Selection) empty() bool {
	return len(s.IDs) == 0 && len(s.Engines) == 0 && len(s.Severities) == 0
}

// describe renders the selection for a report note.
func (s Selection) describe() string {
	var parts []string
	if len(s.IDs) > 0 {
		parts = append(parts, "policies "+strings.Join(s.IDs, ", "))
	}
	if len(s.Engines) > 0 {
		parts = append(parts, "engines "+strings.Join(s.Engines, ", "))
	}
	if len(s.Severities) > 0 {
		parts = append(parts, "severities "+strings.Join(s.Severities, ", "))
	}
	return strings.Join(parts, "; ")
}

// selectPolicies applies a selection to the policies of a pack.
//
// Every entry of the selection must match something. An id, pattern, engine
// or severity that matches nothing is an error, as is a selection whose parts
// have no policy in common. Otherwise a typing mistake would quietly shrink
// the evaluation and make a manifest look more compliant than it is.
func selectPolicies(all []policy.Policy, sel Selection) ([]policy.Policy, error) {
	if sel.empty() {
		return all, nil
	}
	keep := func(p policy.Policy) bool { return true }

	if len(sel.Engines) > 0 {
		for _, want := range sel.Engines {
			if !slices.ContainsFunc(all, func(p policy.Policy) bool { return strings.EqualFold(p.Engine, want) }) {
				return nil, fmt.Errorf("no policy in the pack uses engine %q (engines in the pack: %s)", want, strings.Join(distinct(all, func(p policy.Policy) string { return p.Engine }), ", "))
			}
		}
		prev := keep
		keep = func(p policy.Policy) bool {
			return prev(p) && slices.ContainsFunc(sel.Engines, func(e string) bool { return strings.EqualFold(p.Engine, e) })
		}
	}
	if len(sel.Severities) > 0 {
		for _, want := range sel.Severities {
			if !slices.ContainsFunc(all, func(p policy.Policy) bool { return strings.EqualFold(p.Severity, want) }) {
				return nil, fmt.Errorf("no policy in the pack has severity %q (severities in the pack: %s)", want, strings.Join(distinct(all, func(p policy.Policy) string { return p.Severity }), ", "))
			}
		}
		prev := keep
		keep = func(p policy.Policy) bool {
			return prev(p) && slices.ContainsFunc(sel.Severities, func(s string) bool { return strings.EqualFold(p.Severity, s) })
		}
	}
	if len(sel.IDs) > 0 {
		picked := map[string]bool{}
		for _, want := range sel.IDs {
			var hits []policy.Policy
			wildcard := strings.Contains(want, "*")
			for _, p := range all {
				if p.ID == want || p.Name == want || (wildcard && matchAny([]string{want}, p.ID)) {
					hits = append(hits, p)
				}
			}
			switch {
			case len(hits) == 0 && wildcard:
				return nil, fmt.Errorf("pattern %q matches no policy in the pack; use list_policies to see valid ids", want)
			case len(hits) == 0:
				return nil, fmt.Errorf("policy %q is not in the pack; use list_policies to see valid ids", want)
			case len(hits) > 1 && !wildcard:
				return nil, fmt.Errorf("policy name %q is ambiguous; use the full id", want)
			}
			for _, h := range hits {
				picked[h.ID] = true
			}
		}
		prev := keep
		keep = func(p policy.Policy) bool { return prev(p) && picked[p.ID] }
	}

	var out []policy.Policy
	for _, p := range all {
		if keep(p) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the selection matches no policy: each part matches something, but no policy satisfies all of them (%s)", sel.describe())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// distinct lists the different non-empty values of a policy field, sorted.
func distinct(all []policy.Policy, field func(policy.Policy) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range all {
		if v := field(p); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}

func contextResources(ec evalctx.Context) []manifests.Resource {
	out := make([]manifests.Resource, 0, len(ec.Resources))
	for _, obj := range ec.Resources {
		out = append(out, manifests.Resource{Object: obj})
	}
	return out
}

func stringMap(v any) map[string]string {
	m, _ := v.(map[string]any)
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, x := range m {
		if s, ok := x.(string); ok {
			out[k] = s
		}
	}
	return out
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
