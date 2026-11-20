// Package cli implements the kube-policy-mcp command line. It exists for
// local testing, debugging and CI; it is not a deployment tool.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/cosmosdevops/kube-policy-mcp/internal/app"
	"github.com/cosmosdevops/kube-policy-mcp/internal/engines"
	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/evaluator"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/mcpserver"
)

// Exit codes of the evaluate command.
const (
	ExitCompliant  = 0
	ExitViolations = 1
	ExitIncomplete = 2
	ExitError      = 3
)

// ExitError carries a specific process exit code.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// Main runs the CLI and returns the process exit code.
func Main(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	root := newRoot(stdin)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprintln(stderr, ee.msg)
		}
		return ee.code
	}
	fmt.Fprintln(stderr, "error:", err)
	return ExitError
}

type globals struct {
	config string
	roots  []string
}

func (g *globals) app() (*app.App, error) { return app.New(g.config, g.roots) }

func newRoot(stdin io.Reader) *cobra.Command {
	g := &globals{}
	root := &cobra.Command{
		Use:           "kube-policy-mcp",
		Short:         "Evaluate Kubernetes manifests against organisational policies, offline",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&g.config, "config", "", "config file (default: $"+app.ConfigEnv+" or ./"+app.DefaultConfigFile+")")
	root.PersistentFlags().StringArrayVar(&g.roots, "workspace-root", nil, "extra directory the MCP server may read manifests from (repeatable)")
	root.AddCommand(serveCmd(g), newKeyCmd(), checkHealthCmd(), evaluateCmd(g, stdin), packsCmd(g), policiesCmd(g), policyCmd(g), enginesCmd(), versionCmd())
	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print the version", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), app.Version)
		return nil
	}}
}

// enginesCmd lists the engines in this build. It needs no config file, so
// it also works to inspect a binary.
func enginesCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{Use: "engines", Short: "List the policy engines built into this binary", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		infos := []engines.Info{}
		for _, r := range engines.Registered() {
			infos = append(infos, r.Describe(r.New(), true))
		}
		out := cmd.OutOrStdout()
		if output == "json" {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(infos)
		}
		if len(infos) == 0 {
			fmt.Fprintln(out, "This binary was built without any policy engine.")
		}
		for _, e := range infos {
			version := ""
			if e.UpstreamVersion != "" {
				version = " (upstream " + e.UpstreamVersion + ")"
			}
			fmt.Fprintf(out, "%s: %s%s\n  %s\n", e.Name, e.Title, version, e.Description)
			fmt.Fprintf(out, "  policy types: %s\n  source: %s\n", strings.Join(e.PolicyTypes, ", "), e.SourceFormat)
			if e.NativeExceptions != "" {
				fmt.Fprintf(out, "  exceptions: %s\n", e.NativeExceptions)
			}
			for _, l := range e.Limitations {
				fmt.Fprintf(out, "  limitation: %s\n", l)
			}
		}
		return nil
	}}
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text or json")
	return cmd
}

func serveCmd(g *globals) *cobra.Command {
	var (
		addr, keysFile string
		perMinute      float64
		burst          int
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP server on stdio, or over HTTP with --http",
		Long: `Run the MCP server.

With no flags it talks MCP over stdin/stdout, for an agent to run locally.

With --http it serves MCP over HTTP at /mcp, for hosting. Callers need an API
key from the --keys file, and each key has its own rate limit. Make keys with
the new-key command. /healthz is open and needs no key.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := g.app()
			if err != nil {
				return err
			}
			about := fmt.Sprintf("engines: %s; workspace roots: %s", strings.Join(a.Registry.EngineNames(), ", "), strings.Join(a.Workspace.Roots(), ", "))
			if addr == "" {
				if keysFile != "" {
					return errors.New("--keys only applies with --http")
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "kube-policy-mcp %s: serving MCP on stdio (%s)\n", app.Version, about)
				return mcpserver.Run(cmd.Context(), a)
			}
			if keysFile == "" {
				return errors.New("--http needs --keys: the hosted server only answers callers with an API key")
			}
			log.SetFlags(0)
			log.SetOutput(cmd.ErrOrStderr())
			log.Printf("kube-policy-mcp %s: serving MCP on http://%s/mcp, %g requests a minute per key (%s)", app.Version, addr, perMinute, about)
			return mcpserver.RunHTTP(cmd.Context(), a, mcpserver.HTTPOptions{
				Addr: addr, KeysFile: keysFile, PerMinute: perMinute, Burst: burst, MaxInput: a.Config.Limits.MaxManifestBytes,
			})
		},
	}
	cmd.Flags().StringVar(&addr, "http", "", "serve MCP over HTTP on this address (e.g. 127.0.0.1:8088) instead of stdin/stdout; needs --keys")
	cmd.Flags().StringVar(&keysFile, "keys", "", "file of API keys for --http, one \"name sha256\" per line; add lines with the new-key command")
	cmd.Flags().Float64Var(&perMinute, "rate", 60, "with --http: requests each API key may make per minute")
	cmd.Flags().IntVar(&burst, "burst", 30, "with --http: requests each API key may make at once before the rate applies")
	return cmd
}

// newKeyCmd makes an API key for the hosted mode. It needs no config file.
func newKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "new-key NAME",
		Short: "Make an API key for serve --http",
		Long: `Make an API key for a named holder.

The key is printed once on stderr, for you to pass on. The line for the keys
file is printed on stdout, so it can be appended:

  kube-policy-mcp new-key alice >> /etc/kube-policy-mcp/keys

The keys file holds the name and the SHA-256 of each key, never the key
itself. To revoke a key, delete its line.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, line, err := mcpserver.NewKey(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "API key for %s (shown once, it is not stored):\n\n  %s\n\n", args[0], key)
			fmt.Fprintln(cmd.OutOrStdout(), line)
			return nil
		},
	}
}

// checkHealthCmd asks a running server whether it is up. Container images
// have no curl to do this with.
func checkHealthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check-health URL",
		Short: "Check a running server's health URL; for container health checks",
		Long:  "Ask a running server's health URL (e.g. http://127.0.0.1:8088/healthz) and exit 0 if it is up.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return mcpserver.CheckHealth(args[0])
		},
	}
}

func evaluateCmd(g *globals, stdin io.Reader) *cobra.Command {
	var (
		files       []string
		dir         string
		pack        string
		policies    []string
		contextFile string
		namespace   string
		operation   string
		output      string
		all         bool
		explain     bool
	)
	cmd := &cobra.Command{
		Use:   "evaluate",
		Short: "Evaluate manifests against a policy pack",
		Long: `Evaluate manifests against a policy pack.

Exit codes: 0 compliant, 1 policy violations, 2 incomplete (some checks could
not be decided), 3 usage or runtime error.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := g.app()
			if err != nil {
				return err
			}
			if len(files) == 0 && dir == "" {
				return errors.New("give at least one --file or a --dir")
			}
			var ec evalctx.Context
			if contextFile != "" {
				data, err := os.ReadFile(contextFile)
				if err != nil {
					return err
				}
				// Accept the context at the top level or under a "context" key.
				var wrapper struct {
					Context *evalctx.Context `json:"context"`
				}
				if err := yaml.Unmarshal(data, &wrapper); err == nil && wrapper.Context != nil {
					ec = *wrapper.Context
				} else if err := yaml.UnmarshalStrict(data, &ec); err != nil {
					return fmt.Errorf("context file %s: %w", contextFile, err)
				}
			}
			if namespace != "" {
				if ec.Namespace == nil {
					ec.Namespace = &evalctx.Namespace{}
				}
				ec.Namespace.Name = namespace
			}
			if operation != "" {
				ec.Operation = operation
			}
			lim := a.ManifestLimits()
			var resources []manifests.Resource
			var skipped []findings.SkippedFile
			for _, f := range files {
				var data []byte
				name := f
				if f == "-" {
					data, err = io.ReadAll(io.LimitReader(stdin, lim.MaxBytes+1))
					name = "stdin"
				} else {
					data, err = os.ReadFile(f)
				}
				if err != nil {
					return err
				}
				rs, err := manifests.Parse(data, name, lim)
				if err != nil {
					return err
				}
				resources = append(resources, rs...)
			}
			if dir != "" {
				// The operator chose this directory, so it is the workspace.
				ws, err := manifests.NewWorkspace([]string{dir})
				if err != nil {
					return err
				}
				rs, sk, err := ws.LoadDir(".", a.DirLimits())
				if err != nil {
					return err
				}
				for i := range rs {
					rs[i].Source = filepath.Join(dir, rs[i].Source)
					rs[i].File = filepath.Join(dir, rs[i].File)
				}
				for i := range sk {
					sk[i].Path = filepath.Join(dir, sk[i].Path)
				}
				resources = append(resources, rs...)
				skipped = sk
			}
			res, err := a.Evaluator.Evaluate(cmd.Context(), evaluator.Request{
				Resources: resources, Pack: pack, PolicyIDs: policies, Context: ec, IncludeAll: all, SkippedFiles: skipped,
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			switch output {
			case "json":
				var payload any = res.Report
				if explain {
					exps := []*evaluator.Explanation{}
					for _, f := range res.Report.Findings {
						if ex, err := res.Explain(f.ID); err == nil {
							exps = append(exps, ex)
						}
					}
					payload = map[string]any{"report": res.Report, "explanations": exps}
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(payload); err != nil {
					return err
				}
			case "text":
				printText(out, res, explain)
			default:
				return fmt.Errorf("unknown output format %q (use text or json)", output)
			}
			switch {
			case res.Report.Summary.Violations > 0:
				return &exitError{code: ExitViolations}
			case !res.Report.Complete:
				return &exitError{code: ExitIncomplete}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringArrayVarP(&files, "file", "f", nil, "manifest file to evaluate; use - for stdin (repeatable)")
	f.StringVar(&dir, "dir", "", "evaluate every manifest under this directory")
	f.StringVar(&pack, "policy-pack", "", "policy pack to use (default: the configured default pack)")
	f.StringArrayVar(&policies, "policy", nil, "only evaluate this policy id (repeatable)")
	f.StringVar(&contextFile, "context-file", "", "YAML or JSON file with the simulated evaluation context")
	f.StringVar(&namespace, "namespace", "", "target namespace for resources that do not set one")
	f.StringVar(&operation, "operation", "", "admission operation: CREATE, UPDATE or DELETE")
	f.StringVarP(&output, "output", "o", "text", "output format: text or json")
	f.BoolVar(&all, "all", false, "also list pass and not_applicable results")
	f.BoolVar(&explain, "explain", false, "explain each finding")
	return cmd
}

func printText(w io.Writer, res *evaluator.Result, explain bool) {
	r := res.Report
	fmt.Fprintf(w, "Policy pack: %s\n", r.PolicyPack)
	fmt.Fprintf(w, "Verdict:     %s (complete: %t, compliant: %t)\n", strings.ToUpper(string(r.Status)), r.Complete, r.Compliant)
	s := r.Summary
	fmt.Fprintf(w, "Evaluated:   %d resource(s) against %d policy(ies)\n", s.ResourcesEvaluated, s.PoliciesEvaluated)
	fmt.Fprintf(w, "Results:     %d violation(s), %d warning(s), %d unknown, %d error(s), %d exempted, %d passed, %d not applicable\n\n",
		s.Violations, s.Warnings, s.Unknown, s.Errors, s.Exempted, s.Passed, s.NotApplicable)
	fileOf := map[string]string{}
	for _, mr := range res.Resources {
		fileOf[mr.Ref().Key()] = mr.File
	}
	for _, fg := range findings.GroupBySource(r, func(ref findings.ResourceRef) string { return fileOf[ref.Key()] }) {
		fmt.Fprintf(w, "%s\n", fg.Path)
		for _, rg := range fg.Resources {
			if len(rg.Findings) == 0 {
				fmt.Fprintf(w, "  %s: no findings\n", rg.Resource)
				continue
			}
			fmt.Fprintf(w, "  %s\n", rg.Resource)
			for _, f := range rg.Findings {
				rule := ""
				if f.Rule != "" {
					rule = " [" + f.Rule + "]"
				}
				fmt.Fprintf(w, "    %-14s %s%s\n", strings.ToUpper(string(f.Status)), f.Policy, rule)
				if f.Message != "" {
					fmt.Fprintf(w, "      %s\n", f.Message)
				}
				if f.Field != "" {
					fmt.Fprintf(w, "      field: %s\n", f.Field)
				}
				if f.Exemption != nil {
					fmt.Fprintf(w, "      exempted by: %s (%s) %s\n", f.Exemption.Name, f.Exemption.Source, f.Exemption.Reason)
				}
				if len(f.MissingContext) > 0 {
					fmt.Fprintf(w, "      missing context: %s\n", strings.Join(f.MissingContext, ", "))
				}
				if f.Remediation != nil {
					fmt.Fprintf(w, "      fix: %s\n", f.Remediation.Description)
				}
				if explain {
					if ex, err := res.Explain(f.ID); err == nil {
						if ex.Expected != "" {
							fmt.Fprintf(w, "      expected: %s\n", ex.Expected)
						}
						if ex.Actual != nil {
							if ex.Actual.Found {
								fmt.Fprintf(w, "      actual: %s = %s\n", ex.Actual.Field, ex.Actual.Value)
							} else {
								fmt.Fprintf(w, "      actual: %s is not set\n", ex.Actual.Field)
							}
						}
					}
				}
			}
		}
	}
	for _, sk := range r.SkippedFiles {
		fmt.Fprintf(w, "skipped %s: %s\n", sk.Path, sk.Reason)
	}
	if len(r.Notes) > 0 {
		fmt.Fprintln(w, "\nNotes:")
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
}

func packsCmd(g *globals) *cobra.Command {
	return &cobra.Command{Use: "packs", Short: "List the configured policy packs", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		a, err := g.app()
		if err != nil {
			return err
		}
		for _, p := range a.Registry.Packs() {
			def := ""
			if p.Default {
				def = " (default)"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s%s\n  %s\n", p.Name, def, p.Description)
			if len(p.Extends) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "  extends: %s\n", strings.Join(p.Extends, ", "))
			}
			for _, s := range p.Sources {
				fmt.Fprintf(cmd.OutOrStdout(), "  source: %s %s\n", s.Engine, s.Path)
			}
			if p.Problem != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  NOT USABLE: %s\n", p.Problem)
			}
		}
		return nil
	}}
}

func policiesCmd(g *globals) *cobra.Command {
	var f app.PolicyFilter
	var output string
	cmd := &cobra.Command{Use: "policies", Short: "List the policies of a pack", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		a, err := g.app()
		if err != nil {
			return err
		}
		list, err := a.ListPolicies(cmd.Context(), f)
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if output == "json" {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(list.Policies)
		}
		fmt.Fprintf(out, "Pack %s (resolution order: %s), %d policy(ies)\n\n", list.Pack, strings.Join(list.Chain, " -> "), len(list.Policies))
		for _, p := range list.Policies {
			status := ""
			if !p.Supported {
				status = "  [NOT EVALUABLE: " + p.Problem + "]"
			}
			fmt.Fprintf(out, "%s%s\n", p.ID, status)
			if p.Title != "" {
				fmt.Fprintf(out, "  %s\n", p.Title)
			}
			kinds := "any (not declared)"
			if len(p.Kinds) > 0 {
				kinds = strings.Join(p.Kinds, ", ")
			}
			fmt.Fprintf(out, "  severity: %s  enforcement: %s  kinds: %s\n", orDash(p.Severity), orDash(p.Enforcement), kinds)
			if len(p.RequiredContext) > 0 {
				fmt.Fprintf(out, "  needs context: %s\n", strings.Join(p.RequiredContext, ", "))
			}
		}
		for _, n := range list.Notes {
			fmt.Fprintf(out, "note: %s\n", n)
		}
		return nil
	}}
	fl := cmd.Flags()
	fl.StringVar(&f.Pack, "policy-pack", "", "policy pack (default: the configured default pack)")
	fl.StringVar(&f.Engine, "engine", "", "only this engine")
	fl.StringVar(&f.Kind, "kind", "", "only policies that can apply to this kind")
	fl.StringVar(&f.Severity, "severity", "", "only this severity")
	fl.StringVar(&f.Namespace, "namespace", "", "only policies that can apply in this namespace")
	fl.StringVarP(&output, "output", "o", "text", "output format: text or json")
	return cmd
}

func policyCmd(g *globals) *cobra.Command {
	var pack string
	var definition bool
	cmd := &cobra.Command{Use: "policy <id>", Short: "Show one policy", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		a, err := g.app()
		if err != nil {
			return err
		}
		p, err := a.GetPolicy(cmd.Context(), pack, args[0])
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		b, err := yaml.Marshal(p)
		if err != nil {
			return err
		}
		fmt.Fprint(out, string(b))
		if definition {
			fmt.Fprintf(out, "---\n# definition (%s)\n%s\n", p.SourcePath, p.Raw)
		}
		return nil
	}}
	cmd.Flags().StringVar(&pack, "policy-pack", "", "policy pack (default: the configured default pack)")
	cmd.Flags().BoolVar(&definition, "definition", false, "also print the original policy source")
	return cmd
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
