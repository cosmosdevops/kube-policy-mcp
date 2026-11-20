// Package mcpserver exposes the evaluation core as Model Context Protocol
// tools. It contains no policy logic of its own.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/cosmosdevops/kube-policy-mcp/internal/app"
	"github.com/cosmosdevops/kube-policy-mcp/internal/engines"
	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/evaluator"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/packs"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// instructionsFor builds the server instructions. The engine list comes
// from the engines in this build, so the text is never out of date.
func instructionsFor(infos []engines.Info) string {
	var titles []string
	for _, e := range infos {
		if e.Enabled {
			titles = append(titles, e.Title)
		}
	}
	return fmt.Sprintf(instructions, strings.Join(titles, ", "))
}

const instructions = `This server checks Kubernetes manifests against the organisation's policies without a cluster. Policy engines in this server: %s.

Typical workflow:
1. list_policy_packs to see the available packs.
2. list_policies (optionally filtered by kind) to see what applies.
3. evaluate_manifests with your YAML. Read "status", "complete" and "findings".
4. For each finding, use its remediation text or call explain_violation.
5. Change your manifest and call evaluate_manifests again until "compliant" is true.

How to read results:
- status "fail": at least one enforced policy is violated.
- status "unknown" or complete=false: some checks could not be decided (missing context or an engine error). This is NOT a pass. Supply the missing context listed in the findings and evaluate again.
- "warning" findings do not block compliance. "exempted" findings are covered by an approved exception.
- A policy that does not match a resource is "not_applicable", never "pass".
The server never changes your manifests and never contacts a cluster. Context values you pass are simulated, not verified.`

// maxHistory is how many evaluations are kept for explain_violation.
const maxHistory = 50

// Server holds the MCP tool handlers.
type Server struct {
	app *app.App

	mu      sync.Mutex
	history map[string]*evaluator.Result
	order   []string
}

// New creates the MCP server with all tools registered.
func New(a *app.App) (*Server, *mcp.Server) {
	s := &Server{app: a, history: map[string]*evaluator.Result{}}
	srv := mcp.NewServer(&mcp.Implementation{Name: "kube-policy-mcp", Title: "Kubernetes Policy Evaluation", Version: app.Version}, &mcp.ServerOptions{Instructions: instructionsFor(a.Engines)})
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)}

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_policy_packs",
		Description: "List the configured policy packs (named sets of policies), the default pack, and the policy engines available in this server with their limitations.",
		Annotations: readOnly,
	}, s.listPacks)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_policies",
		Description: "List the policies of a policy pack with their id, engine, description, severity and the resource kinds they apply to. Filter by engine, kind, severity or namespace.",
		Annotations: readOnly,
	}, s.listPolicies)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_policy",
		Description: "Get one policy: purpose, rules, matching criteria, enforcement action, exceptions, required context and remediation guidance. Set includeDefinition to also get the original policy source.",
		Annotations: readOnly,
	}, s.getPolicy)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "evaluate_manifests",
		Description: "Evaluate Kubernetes manifests against a policy pack, offline. Pass inline YAML or JSON (multiple documents allowed) in 'manifests', or workspace file paths in 'files'. Returns the verdict, violations, warnings, checks that could not be decided, and remediation for each finding. Nothing is applied to a cluster and the manifests are not changed.",
		Annotations: readOnly,
	}, s.evaluateManifests)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "evaluate_directory",
		Description: "Evaluate every manifest file (.yaml, .yml, .json) under a workspace directory against a policy pack. Findings are grouped by file and resource. Files that are not Kubernetes manifests are listed as skipped.",
		Annotations: readOnly,
	}, s.evaluateDirectory)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "explain_violation",
		Description: "Explain a finding from an earlier evaluate_manifests or evaluate_directory call: the policy and rule, the resource, the expected behaviour, the observed value and how to fix it. The explanation only uses the policy definition and the evaluation result.",
		Annotations: readOnly,
	}, s.explainViolation)
	return s, srv
}

func ptr[T any](v T) *T { return &v }

// ---- list_policy_packs ----

type listPacksInput struct{}

type listPacksOutput struct {
	DefaultPolicyPack string `json:"defaultPolicyPack,omitempty"`
	// Engines lists the names of the engines that can be used.
	Engines []string `json:"engines"`
	// EngineDetails describes every engine in this build.
	EngineDetails []engines.Info   `json:"engineDetails"`
	PolicyPacks   []packs.PackInfo `json:"policyPacks"`
}

func (s *Server) listPacks(ctx context.Context, _ *mcp.CallToolRequest, _ listPacksInput) (*mcp.CallToolResult, listPacksOutput, error) {
	return nil, listPacksOutput{
		DefaultPolicyPack: s.app.Registry.DefaultPack(),
		Engines:           s.app.Registry.EngineNames(),
		EngineDetails:     s.app.Engines,
		PolicyPacks:       s.app.Registry.Packs(),
	}, nil
}

// ---- list_policies ----

type listPoliciesInput struct {
	PolicyPack string `json:"policyPack,omitempty" jsonschema:"policy pack name; the default pack is used when omitted"`
	Engine     string `json:"engine,omitempty" jsonschema:"only policies of this engine; list_policy_packs shows the engine names"`
	Kind       string `json:"kind,omitempty" jsonschema:"only policies that can apply to this Kubernetes kind, for example Deployment"`
	Severity   string `json:"severity,omitempty" jsonschema:"only policies with this declared severity"`
	Namespace  string `json:"namespace,omitempty" jsonschema:"only policies that can apply in this namespace"`
}

// PolicySummary is the short form of a policy used in listings.
type PolicySummary struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Engine          string   `json:"engine"`
	Type            string   `json:"type"`
	Title           string   `json:"title,omitempty"`
	Description     string   `json:"description,omitempty"`
	Severity        string   `json:"severity,omitempty"`
	Enforcement     string   `json:"enforcement,omitempty"`
	Kinds           []string `json:"kinds,omitempty"`
	RequiredContext []string `json:"requiredContext,omitempty"`
	Pack            string   `json:"pack,omitempty"`
	Supported       bool     `json:"supported"`
	Problem         string   `json:"problem,omitempty"`
}

type listPoliciesOutput struct {
	PolicyPack string          `json:"policyPack"`
	PackChain  []string        `json:"packChain"`
	Count      int             `json:"count"`
	Policies   []PolicySummary `json:"policies"`
	Notes      []string        `json:"notes,omitempty"`
}

func (s *Server) listPolicies(ctx context.Context, _ *mcp.CallToolRequest, in listPoliciesInput) (*mcp.CallToolResult, listPoliciesOutput, error) {
	list, err := s.app.ListPolicies(ctx, app.PolicyFilter{Pack: in.PolicyPack, Engine: in.Engine, Kind: in.Kind, Severity: in.Severity, Namespace: in.Namespace})
	if err != nil {
		return nil, listPoliciesOutput{}, err
	}
	out := listPoliciesOutput{PolicyPack: list.Pack, PackChain: list.Chain, Notes: list.Notes, Policies: []PolicySummary{}}
	for _, p := range list.Policies {
		out.Policies = append(out.Policies, PolicySummary{
			ID: p.ID, Name: p.Name, Engine: p.Engine, Type: p.Type, Title: p.Title, Description: p.Description,
			Severity: p.Severity, Enforcement: p.Enforcement, Kinds: p.Kinds, RequiredContext: p.RequiredContext,
			Pack: p.Pack, Supported: p.Supported, Problem: p.Problem,
		})
	}
	out.Count = len(out.Policies)
	if in.Kind != "" {
		out.Notes = append(out.Notes, "Policies that do not declare the kinds they apply to are included, because they may apply to any kind.")
	}
	return nil, out, nil
}

// ---- get_policy ----

type getPolicyInput struct {
	Policy            string `json:"policy" jsonschema:"policy id from list_policies, in the form engine/name"`
	PolicyPack        string `json:"policyPack,omitempty" jsonschema:"policy pack name; the default pack is used when omitted"`
	IncludeDefinition bool   `json:"includeDefinition,omitempty" jsonschema:"also return the original policy source"`
}

type getPolicyOutput struct {
	Policy     policy.Policy `json:"policy"`
	Definition string        `json:"definition,omitempty"`
}

func (s *Server) getPolicy(ctx context.Context, _ *mcp.CallToolRequest, in getPolicyInput) (*mcp.CallToolResult, getPolicyOutput, error) {
	if in.Policy == "" {
		return nil, getPolicyOutput{}, errors.New("policy is required")
	}
	p, err := s.app.GetPolicy(ctx, in.PolicyPack, in.Policy)
	if err != nil {
		return nil, getPolicyOutput{}, err
	}
	out := getPolicyOutput{Policy: *p}
	if in.IncludeDefinition {
		out.Definition = p.Raw
	}
	return nil, out, nil
}

// ---- evaluate_manifests / evaluate_directory ----

type evalOptions struct {
	IncludeAllResults bool `json:"includeAllResults,omitempty" jsonschema:"also list pass and not_applicable results; by default only findings that need attention are listed"`
}

type evaluateManifestsInput struct {
	Manifests  string           `json:"manifests,omitempty" jsonschema:"inline Kubernetes YAML or JSON; several documents may be separated by ---"`
	Files      []string         `json:"files,omitempty" jsonschema:"manifest file paths inside the workspace, relative to the workspace root"`
	PolicyPack string           `json:"policyPack,omitempty" jsonschema:"policy pack name; the default pack is used when omitted"`
	Policies   []string         `json:"policies,omitempty" jsonschema:"only evaluate these policy ids"`
	Context    *evalctx.Context `json:"context,omitempty" jsonschema:"simulated evaluation context: target namespace and its labels, operation, user, variables and extra resources"`
	Options    *evalOptions     `json:"options,omitempty"`
}

func (s *Server) evaluateManifests(ctx context.Context, _ *mcp.CallToolRequest, in evaluateManifestsInput) (*mcp.CallToolResult, *findings.Report, error) {
	if strings.TrimSpace(in.Manifests) == "" && len(in.Files) == 0 {
		return nil, nil, errors.New("provide inline YAML in 'manifests' or workspace paths in 'files'")
	}
	lim := s.app.ManifestLimits()
	var resources []manifests.Resource
	if strings.TrimSpace(in.Manifests) != "" {
		rs, err := manifests.Parse([]byte(in.Manifests), "inline", lim)
		if err != nil {
			return nil, nil, err
		}
		resources = append(resources, rs...)
	}
	for _, f := range in.Files {
		rs, err := s.app.Workspace.LoadFile(f, lim)
		if err != nil {
			return nil, nil, err
		}
		resources = append(resources, rs...)
	}
	if lim.MaxResources > 0 && len(resources) > lim.MaxResources {
		return nil, nil, fmt.Errorf("more than %d resources in one request", lim.MaxResources)
	}
	res, err := s.evaluate(ctx, resources, in.PolicyPack, in.Policies, in.Context, in.Options, nil)
	if err != nil {
		return nil, nil, err
	}
	return nil, res.Report, nil
}

type evaluateDirectoryInput struct {
	Directory  string           `json:"directory" jsonschema:"directory inside the workspace, relative to the workspace root; use . for the root"`
	PolicyPack string           `json:"policyPack,omitempty" jsonschema:"policy pack name; the default pack is used when omitted"`
	Policies   []string         `json:"policies,omitempty" jsonschema:"only evaluate these policy ids"`
	Context    *evalctx.Context `json:"context,omitempty" jsonschema:"simulated evaluation context"`
	Options    *evalOptions     `json:"options,omitempty"`
}

// DirectoryReport is a report whose findings are grouped by file and resource.
type DirectoryReport struct {
	EvaluationID  string                  `json:"evaluationId"`
	Status        findings.Status         `json:"status"`
	Complete      bool                    `json:"complete"`
	Compliant     bool                    `json:"compliant"`
	PolicyPack    string                  `json:"policyPack"`
	Directory     string                  `json:"directory"`
	Summary       findings.Summary        `json:"summary"`
	PolicyResults []findings.PolicyResult `json:"policyResults"`
	Files         []findings.FileGroup    `json:"files"`
	SkippedFiles  []findings.SkippedFile  `json:"skippedFiles,omitempty"`
	Notes         []string                `json:"notes,omitempty"`
}

func (s *Server) evaluateDirectory(ctx context.Context, _ *mcp.CallToolRequest, in evaluateDirectoryInput) (*mcp.CallToolResult, *DirectoryReport, error) {
	if in.Directory == "" {
		return nil, nil, errors.New("directory is required")
	}
	resources, skipped, err := s.app.Workspace.LoadDir(in.Directory, s.app.DirLimits())
	if err != nil {
		return nil, nil, err
	}
	if len(resources) == 0 {
		return nil, nil, fmt.Errorf("no Kubernetes manifests found under %s (%d file(s) skipped)", in.Directory, len(skipped))
	}
	res, err := s.evaluate(ctx, resources, in.PolicyPack, in.Policies, in.Context, in.Options, skipped)
	if err != nil {
		return nil, nil, err
	}
	return nil, Directory(res, in.Directory), nil
}

// Directory converts a result into the grouped directory form.
func Directory(res *evaluator.Result, dir string) *DirectoryReport {
	r := res.Report
	fileOf := map[string]string{}
	for _, mr := range res.Resources {
		fileOf[mr.Ref().Key()] = mr.File
	}
	return &DirectoryReport{
		EvaluationID: r.EvaluationID, Status: r.Status, Complete: r.Complete, Compliant: r.Compliant,
		PolicyPack: r.PolicyPack, Directory: dir, Summary: r.Summary, PolicyResults: r.PolicyResults,
		Files:        findings.GroupBySource(r, func(ref findings.ResourceRef) string { return fileOf[ref.Key()] }),
		SkippedFiles: r.SkippedFiles, Notes: r.Notes,
	}
}

func (s *Server) evaluate(ctx context.Context, resources []manifests.Resource, pack string, policies []string, ec *evalctx.Context, opts *evalOptions, skipped []findings.SkippedFile) (*evaluator.Result, error) {
	req := evaluator.Request{Resources: resources, Pack: pack, PolicyIDs: policies, SkippedFiles: skipped}
	if ec != nil {
		req.Context = *ec
	}
	if opts != nil {
		req.IncludeAll = opts.IncludeAllResults
	}
	res, err := s.app.Evaluator.Evaluate(ctx, req)
	if err != nil {
		return nil, err
	}
	s.remember(res)
	return res, nil
}

func (s *Server) remember(res *evaluator.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := res.Report.EvaluationID
	s.history[id] = res
	s.order = append(s.order, id)
	for len(s.order) > maxHistory {
		delete(s.history, s.order[0])
		s.order = s.order[1:]
	}
}

// ---- explain_violation ----

type explainInput struct {
	FindingID string `json:"findingId" jsonschema:"the id of a finding from an earlier evaluation, for example f-1a2b3c4d-003"`
}

func (s *Server) explainViolation(ctx context.Context, _ *mcp.CallToolRequest, in explainInput) (*mcp.CallToolResult, *evaluator.Explanation, error) {
	// Finding ids have the form f-<evaluationId>-<number>.
	parts := strings.Split(in.FindingID, "-")
	if len(parts) != 3 || parts[0] != "f" {
		return nil, nil, fmt.Errorf("%q is not a finding id; use the id field of a finding returned by evaluate_manifests", in.FindingID)
	}
	s.mu.Lock()
	res, ok := s.history[parts[1]]
	s.mu.Unlock()
	if !ok {
		return nil, nil, fmt.Errorf("evaluation %s is no longer available (only the last %d evaluations of this session are kept); evaluate again and use the new finding id", parts[1], maxHistory)
	}
	ex, err := res.Explain(in.FindingID)
	if err != nil {
		return nil, nil, err
	}
	return nil, ex, nil
}

// Run serves MCP over stdio until the client disconnects.
func Run(ctx context.Context, a *app.App) error {
	_, srv := New(a)
	return srv.Run(ctx, &mcp.StdioTransport{})
}
