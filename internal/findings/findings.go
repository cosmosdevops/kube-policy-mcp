// Package findings defines the engine-neutral result model shared by every
// policy engine, the evaluator, the CLI and the MCP server.
package findings

import "sort"

// Status is the outcome of one policy rule evaluated against one resource.
type Status string

const (
	// StatusPass: the policy applied to the resource and the resource complied.
	StatusPass Status = "pass"
	// StatusFail: the policy applied and the resource violated an enforced rule.
	StatusFail Status = "fail"
	// StatusWarning: the policy applied and the resource violated a rule that
	// only warns or audits. It does not block the compliance verdict.
	StatusWarning Status = "warning"
	// StatusNotApplicable: the policy does not match this resource. This is
	// never reported as a pass.
	StatusNotApplicable Status = "not_applicable"
	// StatusExempted: the resource violated or would have been checked by the
	// policy, but an exception or exemption covers it.
	StatusExempted Status = "exempted"
	// StatusUnknown: compliance could not be determined, for example because
	// required context was not supplied or the check is unsupported offline.
	StatusUnknown Status = "unknown"
	// StatusError: the engine failed while evaluating. Never treated as a pass.
	StatusError Status = "error"
)

// AllStatuses lists every status in display order.
var AllStatuses = []Status{StatusFail, StatusError, StatusUnknown, StatusWarning, StatusExempted, StatusPass, StatusNotApplicable}

// Actionable reports whether a finding needs the caller's attention.
func (s Status) Actionable() bool {
	switch s {
	case StatusFail, StatusWarning, StatusUnknown, StatusError, StatusExempted:
		return true
	}
	return false
}

// ResourceRef identifies a Kubernetes resource inside a request.
type ResourceRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	// Source is the file (and document index) the resource came from.
	Source string `json:"source,omitempty"`
}

// Key returns a stable identity string for the resource.
func (r ResourceRef) Key() string {
	return r.Source + "|" + r.APIVersion + "|" + r.Kind + "|" + r.Namespace + "|" + r.Name
}

// String renders Kind/namespace/name.
func (r ResourceRef) String() string {
	if r.Namespace != "" {
		return r.Kind + "/" + r.Namespace + "/" + r.Name
	}
	return r.Kind + "/" + r.Name
}

// Remediation tells the caller how to fix a finding. It is always derived
// from policy metadata or engine output, never generated freely.
type Remediation struct {
	Description string `json:"description"`
	// Source says where the text came from: "rule-result", "policy-metadata"
	// or "derived-from-message".
	Source string   `json:"source"`
	Docs   []string `json:"docs,omitempty"`
}

// Exemption records which exception covered a finding.
type Exemption struct {
	Name   string `json:"name"`
	Reason string `json:"reason,omitempty"`
	// Source is "pack-exemption" for exemptions from the configuration, or
	// an engine-defined value for the engine's native exceptions.
	Source string `json:"source"`
}

// Finding is one policy rule result for one resource.
type Finding struct {
	ID          string      `json:"id"`
	Engine      string      `json:"engine"`
	Policy      string      `json:"policy"`
	Rule        string      `json:"rule,omitempty"`
	Resource    ResourceRef `json:"resource"`
	Status      Status      `json:"status"`
	Severity    string      `json:"severity,omitempty"`
	Enforcement string      `json:"enforcement,omitempty"`
	Field       string      `json:"field,omitempty"`
	Message     string      `json:"message,omitempty"`
	// MissingContext lists context the policy needed but was not given.
	MissingContext []string     `json:"missingContext,omitempty"`
	Remediation    *Remediation `json:"remediation,omitempty"`
	Exemption      *Exemption   `json:"exemption,omitempty"`
	// Details keeps original engine diagnostics that may help debugging.
	Details map[string]any `json:"details,omitempty"`
}

// Summary counts results in a report.
type Summary struct {
	ResourcesEvaluated int `json:"resourcesEvaluated"`
	PoliciesEvaluated  int `json:"policiesEvaluated"`
	Violations         int `json:"violations"`
	Warnings           int `json:"warnings"`
	Unknown            int `json:"unknown"`
	Errors             int `json:"errors"`
	Exempted           int `json:"exempted"`
	Passed             int `json:"passed"`
	NotApplicable      int `json:"notApplicable"`
}

// PolicyResult summarises one policy across all resources.
type PolicyResult struct {
	Policy      string         `json:"policy"`
	Engine      string         `json:"engine"`
	Title       string         `json:"title,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	Enforcement string         `json:"enforcement,omitempty"`
	Results     map[Status]int `json:"results"`
}

// SkippedFile is a file that was found but not evaluated.
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Report is the result of one evaluation request.
type Report struct {
	EvaluationID string `json:"evaluationId"`
	// Status is the verdict: "fail" if any enforced rule failed, otherwise
	// "unknown" if the evaluation is incomplete, otherwise "warning" or "pass".
	Status Status `json:"status"`
	// Complete is false when any check ended as unknown or error. It is
	// reported separately from the verdict.
	Complete bool `json:"complete"`
	// Compliant is true only when nothing failed and the evaluation is complete.
	Compliant     bool           `json:"compliant"`
	PolicyPack    string         `json:"policyPack"`
	Summary       Summary        `json:"summary"`
	Resources     []ResourceRef  `json:"resources"`
	PolicyResults []PolicyResult `json:"policyResults"`
	// Findings holds the actionable findings by default (fail, warning,
	// unknown, error, exempted). Pass and not_applicable results are included
	// only when requested.
	Findings     []Finding     `json:"findings"`
	SkippedFiles []SkippedFile `json:"skippedFiles,omitempty"`
	// Notes lists limitations and assumptions that applied to this evaluation.
	Notes []string `json:"notes,omitempty"`
}

// Aggregate fills Status, Complete, Compliant and Summary counts from all
// findings (including pass and not_applicable ones).
func Aggregate(r *Report, all []Finding) {
	s := &r.Summary
	for _, f := range all {
		switch f.Status {
		case StatusFail:
			s.Violations++
		case StatusWarning:
			s.Warnings++
		case StatusUnknown:
			s.Unknown++
		case StatusError:
			s.Errors++
		case StatusExempted:
			s.Exempted++
		case StatusPass:
			s.Passed++
		case StatusNotApplicable:
			s.NotApplicable++
		}
	}
	r.Complete = s.Unknown == 0 && s.Errors == 0
	switch {
	case s.Violations > 0:
		r.Status = StatusFail
	case !r.Complete:
		r.Status = StatusUnknown
	case s.Warnings > 0:
		r.Status = StatusWarning
	default:
		r.Status = StatusPass
	}
	r.Compliant = s.Violations == 0 && r.Complete
}

// FileGroup groups findings by source file and resource.
type FileGroup struct {
	Path      string          `json:"path"`
	Resources []ResourceGroup `json:"resources"`
}

// ResourceGroup holds the findings for one resource.
type ResourceGroup struct {
	Resource ResourceRef `json:"resource"`
	Status   Status      `json:"status"`
	Findings []Finding   `json:"findings"`
}

// GroupBySource arranges the report's findings by file and resource. Every
// evaluated resource appears, even when it has no listed findings.
func GroupBySource(r *Report, filePath func(ResourceRef) string) []FileGroup {
	byRes := map[string][]Finding{}
	for _, f := range r.Findings {
		byRes[f.Resource.Key()] = append(byRes[f.Resource.Key()], f)
	}
	files := map[string]*FileGroup{}
	var order []string
	for _, ref := range r.Resources {
		p := filePath(ref)
		g, ok := files[p]
		if !ok {
			g = &FileGroup{Path: p}
			files[p] = g
			order = append(order, p)
		}
		fs := byRes[ref.Key()]
		if fs == nil {
			fs = []Finding{}
		}
		g.Resources = append(g.Resources, ResourceGroup{Resource: ref, Status: worst(fs), Findings: fs})
	}
	sort.Strings(order)
	out := make([]FileGroup, 0, len(order))
	for _, p := range order {
		out = append(out, *files[p])
	}
	return out
}

func worst(fs []Finding) Status {
	rank := map[Status]int{StatusFail: 6, StatusError: 5, StatusUnknown: 4, StatusWarning: 3, StatusExempted: 2, StatusPass: 1, StatusNotApplicable: 0}
	best := StatusPass
	for _, f := range fs {
		if rank[f.Status] > rank[best] {
			best = f.Status
		}
	}
	return best
}
