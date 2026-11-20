package evaluator

import (
	"fmt"
	"strings"

	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// Explanation describes one finding using only the policy definition and the
// evaluation result. Fields are left empty when the facts are not available.
type Explanation struct {
	Finding findings.Finding `json:"finding"`
	Policy  ExplainedPolicy  `json:"policy"`
	// Rule is the policy rule that produced the finding, when identified.
	Rule *policy.Rule `json:"rule,omitempty"`
	// Summary is a one-sentence statement of what happened.
	Summary string `json:"summary"`
	// Expected states the compliant behaviour, quoted from the policy.
	Expected string `json:"expected,omitempty"`
	// Actual describes the observed input.
	Actual         *Observed             `json:"actual,omitempty"`
	MissingContext []string              `json:"missingContext,omitempty"`
	Remediation    *findings.Remediation `json:"remediation,omitempty"`
	Exemption      *findings.Exemption   `json:"exemption,omitempty"`
	// Limitations lists what could not be established.
	Limitations []string `json:"limitations,omitempty"`
}

// ExplainedPolicy is the policy summary shown in an explanation.
type ExplainedPolicy struct {
	ID          string   `json:"id"`
	Engine      string   `json:"engine"`
	Type        string   `json:"type"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Enforcement string   `json:"enforcement,omitempty"`
	SourcePath  string   `json:"sourcePath,omitempty"`
	Docs        []string `json:"docs,omitempty"`
}

// Observed is the value found at the finding's field.
type Observed struct {
	Field string `json:"field"`
	Found bool   `json:"found"`
	Value string `json:"value,omitempty"`
}

// Explain builds the explanation for a finding of this result.
func (r *Result) Explain(findingID string) (*Explanation, error) {
	var f *findings.Finding
	for i := range r.All {
		if r.All[i].ID == findingID {
			f = &r.All[i]
			break
		}
	}
	if f == nil {
		return nil, fmt.Errorf("finding %q is not part of evaluation %s", findingID, r.Report.EvaluationID)
	}
	p := r.Policies[f.Policy]
	ex := &Explanation{
		Finding: *f,
		Policy: ExplainedPolicy{ID: p.ID, Engine: p.Engine, Type: p.Type, Title: p.Title, Description: p.Description,
			Severity: p.Severity, Enforcement: p.Enforcement, SourcePath: p.SourcePath, Docs: p.Docs},
		MissingContext: f.MissingContext,
		Remediation:    f.Remediation,
		Exemption:      f.Exemption,
	}
	// Match the rule by id. A finding's rule may be "<rule id>/<detail>" when
	// one rule reports several distinct results.
	ruleID, _, _ := strings.Cut(f.Rule, "/")
	for i := range p.Rules {
		if p.Rules[i].ID == f.Rule || p.Rules[i].ID == ruleID {
			ex.Rule = &p.Rules[i]
			break
		}
	}

	res := f.Resource.String()
	switch f.Status {
	case findings.StatusFail:
		ex.Summary = fmt.Sprintf("%s violates policy %s: %s", res, p.ID, f.Message)
	case findings.StatusWarning:
		ex.Summary = fmt.Sprintf("%s does not meet policy %s, which only warns (enforcement %q): %s", res, p.ID, f.Enforcement, f.Message)
	case findings.StatusExempted:
		name := ""
		if f.Exemption != nil {
			name = f.Exemption.Name
		}
		ex.Summary = fmt.Sprintf("%s is exempted from policy %s by %s.", res, p.ID, name)
	case findings.StatusUnknown:
		ex.Summary = fmt.Sprintf("Compliance of %s with policy %s could not be determined: %s", res, p.ID, f.Message)
	case findings.StatusError:
		ex.Summary = fmt.Sprintf("Policy %s could not be evaluated for %s: %s. This is not a pass.", p.ID, res, f.Message)
	case findings.StatusNotApplicable:
		ex.Summary = fmt.Sprintf("Policy %s does not apply to %s. %s", p.ID, res, f.Message)
	case findings.StatusPass:
		ex.Summary = fmt.Sprintf("%s complies with policy %s.", res, p.ID)
	}

	switch {
	case ex.Rule != nil && ex.Rule.Expression != "":
		ex.Expected = "This CEL expression must evaluate to true: " + ex.Rule.Expression
	case ex.Rule != nil && ex.Rule.Description != "":
		ex.Expected = ex.Rule.Description
	case p.Description != "":
		ex.Expected = p.Description
	default:
		ex.Limitations = append(ex.Limitations, "The policy declares no description, so the expected behaviour can only be read from the message or the policy source (get_policy with includeDefinition).")
	}
	// Some engines cannot name the exact condition a rule checks. That is a
	// property of the rule metadata, not of a particular engine.
	violated := f.Status == findings.StatusFail || f.Status == findings.StatusWarning
	if violated && (ex.Rule == nil || ex.Rule.Expression == "") {
		ex.Limitations = append(ex.Limitations, "The engine does not expose the exact condition this rule checks; read the policy source with get_policy (includeDefinition) for the logic.")
	}

	if f.Field != "" {
		obs := &Observed{Field: f.Field}
		for _, mr := range r.Resources {
			if mr.Ref().Key() == f.Resource.Key() {
				obs.Value, obs.Found = manifests.Observed(mr, f.Field, r.Redactor)
				break
			}
		}
		ex.Actual = obs
	} else if f.Status == findings.StatusFail || f.Status == findings.StatusWarning {
		ex.Limitations = append(ex.Limitations, "The policy did not report which field is at fault, so the observed value cannot be shown.")
	}
	return ex, nil
}
