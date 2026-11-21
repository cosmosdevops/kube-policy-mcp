#!/usr/bin/env python3
"""Check Kubernetes manifests in CI with two MCP servers.

    check_manifests.py --config kube-policy-mcp.yaml PATH [PATH...]

Each file goes through two checks:

  1. ojs-mcp: is it valid against the Kubernetes and OpenShift schemas?
  2. kube-policy-mcp: does it comply with the organisation's policies?

A file that fails the schema check is not sent to the policy check, because
policies assume a well-formed manifest.

Problems are printed as GitHub Actions annotations, so they show up on the
pull request. Exit codes: 0 everything passed, 1 something failed or could
not be decided, 3 a server could not be used.
"""

import argparse
import json
import pathlib
import sys

from mcp_call import ServerError, ToolError, call


def annotate(level, file, title, message):
    """Print a GitHub Actions annotation. Outside Actions it is just a line."""
    message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{level} file={file},title={title}::{message}")


def manifests(paths):
    for path in map(pathlib.Path, paths):
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.suffix in (".yaml", ".yml", ".json"))
        else:
            yield path


def check_schema(file, text, args):
    arguments = {"yaml": text}
    if args.openshift_version:
        arguments["version"] = args.openshift_version
    report = call("validate", arguments, [args.ojs_mcp])
    ok = True
    for result in report["results"]:
        what = f'{result.get("kind", "document")} {result.get("name", result["document"])}'
        if result["status"] == "valid":
            continue
        if result["status"] == "skipped":
            annotate("warning", file, "No schema", f"{what}: no schema for this kind, so it was not checked")
            continue
        ok = False
        for problem in result.get("problems") or [{"message": result["status"]}]:
            where = problem.get("path") or "the document"
            annotate("error", file, "Schema", f'{what}: {where}: {problem["message"]}')
    return ok, f'OpenShift {report["openshift"]}'


def check_policy(file, text, args, context):
    arguments = {"manifests": text}
    if args.policy_pack:
        arguments["policyPack"] = args.policy_pack
    if context:
        arguments["context"] = context
    report = call("evaluate_manifests", arguments, [args.kube_policy_mcp, "serve", "--config", args.config])
    for finding in report["findings"]:
        resource = finding["resource"]
        what = f'{resource["kind"]} {resource["name"]}'
        text_ = f'{what}: {finding.get("message", finding["status"])}'
        if finding.get("remediation"):
            text_ += f'\nFix: {finding["remediation"]["description"]}'
        level = {"fail": "error", "unknown": "error", "error": "error", "warning": "warning"}.get(finding["status"], "notice")
        annotate(level, file, finding["policy"], text_)
    summary = report["summary"]
    detail = (f'{summary["policiesEvaluated"]} policies: {summary["violations"]} violations, '
              f'{summary["warnings"]} warnings, {summary["unknown"] + summary["errors"]} undecided')
    # compliant is true only when nothing failed and every check was decided.
    return report["compliant"], detail


def main() -> int:
    parser = argparse.ArgumentParser(description="Check manifests against schemas and policies.")
    parser.add_argument("paths", nargs="+", help="manifest files or directories")
    parser.add_argument("--config", required=True, help="kube-policy-mcp config file")
    parser.add_argument("--policy-pack", help="policy pack to use; default: the config's default pack")
    parser.add_argument("--context-file", help="JSON file with the evaluation context, such as namespace labels")
    parser.add_argument("--openshift-version", help="OpenShift version for the schemas; default: the newest")
    parser.add_argument("--ojs-mcp", default="ojs-mcp", help="the ojs-mcp program")
    parser.add_argument("--kube-policy-mcp", default="kube-policy-mcp", help="the kube-policy-mcp program")
    args = parser.parse_args()

    context = json.loads(pathlib.Path(args.context_file).read_text()) if args.context_file else None
    files = list(manifests(args.paths))
    if not files:
        print("no manifest files found", file=sys.stderr)
        return 3

    failed = 0
    for file in files:
        text = file.read_text()
        try:
            schema_ok, schema_detail = check_schema(file, text, args)
            if schema_ok:
                policy_ok, policy_detail = check_policy(file, text, args, context)
            else:
                policy_ok, policy_detail = None, "not run, fix the schema errors first"
        except ToolError as err:
            annotate("error", file, "Check failed", str(err))
            failed += 1
            continue
        except ServerError as err:
            print(err, file=sys.stderr)
            return 3
        ok = schema_ok and policy_ok
        failed += not ok
        print(f'{"PASS" if ok else "FAIL"}  {file}')
        print(f'      schema: {"valid" if schema_ok else "invalid"} ({schema_detail})')
        print(f'      policy: {"compliant" if policy_ok else "skipped" if policy_ok is None else "not compliant"} ({policy_detail})')

    print(f"\n{len(files) - failed} of {len(files)} file(s) passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
