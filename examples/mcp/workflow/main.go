// Command workflow is a scripted MCP client that walks through the agent
// workflow: discover policies, evaluate a proposed manifest, read the
// findings, then evaluate a corrected manifest.
//
// Usage (from the repository root, after "make build"):
//
//	go run ./examples/mcp/workflow
//
// A real coding agent does the same steps, but writes the fix itself from
// the findings. Here the "proposed" and "corrected" manifests are files so
// that the run is repeatable.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	binary := flag.String("binary", "./bin/kube-policy-mcp", "path to the kube-policy-mcp binary")
	config := flag.String("config", "./examples/kube-policy-mcp.yaml", "server config file")
	proposed := flag.String("proposed", "./examples/manifests/noncompliant/web.yaml", "the agent's first draft")
	corrected := flag.String("corrected", "./examples/manifests/compliant/web.yaml", "the agent's corrected manifest")
	flag.Parse()

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "workflow-demo", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: exec.Command(*binary, "serve", "--config", *config)}, nil)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer session.Close()

	call := func(tool string, args map[string]any) map[string]any {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			log.Fatalf("%s: %v", tool, err)
		}
		if res.IsError {
			log.Fatalf("%s returned an error: %s", tool, res.Content[0].(*mcp.TextContent).Text)
		}
		raw, _ := json.Marshal(res.StructuredContent)
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			log.Fatalf("%s: %v", tool, err)
		}
		return out
	}
	step := func(n int, title string) { fmt.Printf("\n== Step %d: %s ==\n", n, title) }

	step(1, "connect")
	info := session.InitializeResult()
	fmt.Printf("connected to %s %s (protocol %s)\n", info.ServerInfo.Name, info.ServerInfo.Version, info.ProtocolVersion)

	step(2, "discover policy packs (list_policy_packs)")
	packs := call("list_policy_packs", nil)
	for _, p := range packs["policyPacks"].([]any) {
		pack := p.(map[string]any)
		fmt.Printf("- %s: %s\n", pack["name"], pack["description"])
	}
	fmt.Printf("default pack: %s\n", packs["defaultPolicyPack"])

	step(3, "inspect the policies that apply to a Deployment (list_policies)")
	list := call("list_policies", map[string]any{"kind": "Deployment"})
	for _, p := range list["policies"].([]any) {
		pol := p.(map[string]any)
		fmt.Printf("- %-58s %-7s %s\n", pol["id"], pol["severity"], pol["title"])
	}

	step(4, "evaluate the proposed Deployment (evaluate_manifests)")
	draft, err := os.ReadFile(*proposed)
	if err != nil {
		log.Fatal(err)
	}
	report := call("evaluate_manifests", map[string]any{"manifests": string(draft)})
	printVerdict(report)
	seen := map[string]bool{}
	var firstFail string
	for _, f := range report["findings"].([]any) {
		fd := f.(map[string]any)
		if firstFail == "" && fd["status"] == "fail" && fd["field"] != nil {
			firstFail = fd["id"].(string)
		}
		fmt.Printf("- [%s] %s: %s\n", fd["status"], fd["policy"], fd["message"])
		if r, ok := fd["remediation"].(map[string]any); ok && !seen[fd["policy"].(string)] {
			fmt.Printf("    fix: %s\n", r["description"])
		}
		seen[fd["policy"].(string)] = true
	}

	step(5, "explain one violation (explain_violation)")
	ex := call("explain_violation", map[string]any{"findingId": firstFail})
	fmt.Printf("summary:  %s\n", ex["summary"])
	if v, ok := ex["expected"]; ok {
		fmt.Printf("expected: %s\n", v)
	}
	if a, ok := ex["actual"].(map[string]any); ok {
		fmt.Printf("actual:   %s = %v (found: %v)\n", a["field"], a["value"], a["found"])
	}

	step(6, "evaluate the corrected Deployment (evaluate_manifests)")
	fixed, err := os.ReadFile(*corrected)
	if err != nil {
		log.Fatal(err)
	}
	report = call("evaluate_manifests", map[string]any{"manifests": string(fixed)})
	printVerdict(report)
	if report["compliant"] != true {
		log.Fatal("the corrected manifest is still not compliant")
	}
	fmt.Println("\nThe corrected manifest complies with the pack. No cluster was contacted.")
}

func printVerdict(report map[string]any) {
	s := report["summary"].(map[string]any)
	fmt.Printf("verdict: %s (complete: %v, compliant: %v)\n", strings.ToUpper(report["status"].(string)), report["complete"], report["compliant"])
	fmt.Printf("%v resource(s), %v policies: %v violation(s), %v warning(s), %v unknown, %v passed, %v not applicable\n",
		s["resourcesEvaluated"], s["policiesEvaluated"], s["violations"], s["warnings"], s["unknown"], s["passed"], s["notApplicable"])
}
