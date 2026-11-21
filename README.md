# kube-policy-mcp

An MCP server that checks Kubernetes manifests against your organisation's
policies, so an AI coding agent can find and fix violations before anything
reaches a cluster.

It runs the policies you already have, using the upstream engines:

- OPA / Rego
- OPA Gatekeeper
- Kubernetes ValidatingAdmissionPolicy

It works offline. It does not contact a cluster and does not apply anything.
For each violation the agent gets the policy, the field, the reason and the
fix. A check that could not be decided is reported as `unknown` or `error`,
not as a pass.

It does not validate manifests against the Kubernetes schemas. Use a schema
validator for that.

## Install

With Go 1.27 or newer:

```bash
go install github.com/cosmosdevops/kube-policy-mcp/cmd/kube-policy-mcp@latest
```

Or use the container image, `ghcr.io/cosmosdevops/kube-policy-mcp`. See
[docs/hosting.md](docs/hosting.md#using-the-image-locally).

## Try it

The repository has example policies and manifests.

```bash
git clone https://github.com/cosmosdevops/kube-policy-mcp.git
cd kube-policy-mcp
make build
./bin/kube-policy-mcp evaluate --config examples/kube-policy-mcp.yaml --file examples/manifests/noncompliant/web.yaml
```

```text
Policy pack: platform-baseline
Verdict:     FAIL (complete: true, compliant: false)
Evaluated:   1 resource(s) against 11 policy(ies)
Results:     15 violation(s), 3 warning(s), 0 unknown, 0 error(s), 0 exempted, 0 passed, 0 not applicable

examples/manifests/noncompliant/web.yaml
  Deployment/default/web
    ...
    FAIL           opa/kubernetes.approved_registries [deny]
      container "web" uses image "nginx:latest", which is not from an approved registry
      field: spec.template.spec.containers[0].image
      fix: Use an image from one of the approved registries listed in the policy data, or ask the platform team to mirror the image.
    ...
```

`make demo` runs the whole agent loop against the real server: list the
policies, evaluate a draft, read the findings, evaluate the fix.
[docs/agent-workflow.md](docs/agent-workflow.md) has the output.

## Use it with an agent

The server speaks MCP over stdio. For Claude Code:

```bash
claude mcp add kube-policy -- kube-policy-mcp serve --config /path/to/kube-policy-mcp.yaml --workspace-root .
```

Or in `.mcp.json`:

```json
{
  "mcpServers": {
    "kube-policy": {
      "command": "kube-policy-mcp",
      "args": ["serve", "--config", "/path/to/kube-policy-mcp.yaml", "--workspace-root", "."]
    }
  }
}
```

Other MCP clients take the same command and arguments.
[examples/mcp](examples/mcp) has sample client configs.

`--workspace-root` adds a directory the server may read manifests from. With
no such directory, callers send manifests inline.

Then ask in plain words, for example "check this Deployment against our
policies and fix what fails".

### Tools

| Tool | What it does |
| --- | --- |
| `list_policy_packs` | Lists the packs, the default pack and the engines. |
| `list_policies` | Lists the policies of a pack. Filters by engine, kind, severity or namespace. |
| `get_policy` | Shows one policy: rules, matching, enforcement, required context and fix. Can include the source. |
| `evaluate_manifests` | Evaluates inline YAML or JSON, or workspace files. |
| `evaluate_directory` | Evaluates every manifest under a workspace directory. |
| `explain_violation` | Explains one finding: the rule, what was expected, what was found, the fix. |

### Results

A report has a verdict and says separately whether it is complete.

- `status` is `fail`, `unknown`, `warning` or `pass`.
- `complete` is `false` if any check ended as `unknown` or `error`.
- `compliant` is `true` only when nothing failed and the report is complete.

Each finding has one of seven statuses:

| Status | Meaning |
| --- | --- |
| `pass` | The policy applied and the resource complied. |
| `fail` | An enforced rule was violated. |
| `warning` | A warn-only or audit-only rule was violated. Does not block compliance. |
| `not_applicable` | The policy does not match this resource. |
| `exempted` | An approved exception covers the resource. |
| `unknown` | Could not be decided: context is missing, or the check cannot run offline. |
| `error` | The engine or the policy failed. |

[docs/evaluation.md](docs/evaluation.md) has a full result and the details.

### Checking only some policies

Both evaluation tools check the whole pack unless you narrow it:

| Input | CLI flag | Example |
| --- | --- | --- |
| `policies` | `--policy` | `vap/disallow-host-namespaces`, `gatekeeper/*` |
| `engines` | `--engine` | `opa` |
| `severities` | `--severity` | `high` |

A selection that matches nothing is an error, so a typing mistake cannot
shrink the check unnoticed. See
[docs/evaluation.md](docs/evaluation.md#checking-against-some-policies-only).

### Context

Some policies depend on more than the manifest, such as the labels of the
target namespace or a ConfigMap in the cluster. Pass those as `context`.
Without them, the affected checks are `unknown` and say what is missing. See
[docs/evaluation.md](docs/evaluation.md#context).

## Configuration

One YAML file names the policy packs and where their policies are.

```yaml
defaultPolicyPack: platform-baseline
policyPacks:
  - name: platform-baseline
    sources:
      - engine: opa
        path: ./policies/rego
      - engine: vap
        path: ./policies/vap
      - engine: gatekeeper
        path: ./policies/gatekeeper
  - name: production
    extends: [platform-baseline]
    sources:
      - engine: opa
        path: ./policies/production/rego
```

The file is taken from `--config`, then `$KUBE_POLICY_MCP_CONFIG`, then
`./kube-policy-mcp.yaml`. Policy directories come only from this file, never
from MCP arguments.

[docs/configuration.md](docs/configuration.md) covers workspace roots,
limits, pack precedence and exemptions.
[docs/policy-authoring.md](docs/policy-authoring.md) covers what the server
reads from each kind of policy.

## Command line

The CLI runs the same code as the MCP server. It is useful for trying
policies and for CI.

```bash
kube-policy-mcp evaluate --file deployment.yaml
kube-policy-mcp evaluate --dir ./k8s --policy-pack production --output json
kube-policy-mcp evaluate --file app.yaml --engine opa --severity high
kube-policy-mcp evaluate --file app.yaml --context-file context.yaml --explain
cat app.yaml | kube-policy-mcp evaluate --file - --namespace payments
kube-policy-mcp policies --kind Deployment
kube-policy-mcp policy vap/require-run-as-non-root --definition
kube-policy-mcp packs
kube-policy-mcp engines
```

`evaluate` exits with `0` when compliant, `1` on violations, `2` when
nothing failed but some checks are `unknown` or `error`, and `3` on a usage
or runtime error.

[examples/ci](examples/ci) has an example GitHub Actions workflow that checks
manifests on every pull request, first against the schemas with
[ojs-mcp](https://github.com/cosmosdevops/ojs-mcp) and then against the
policies. `make check-manifests` runs it on your machine.

## Hosting

`serve --http` runs one server for many agents. Each caller needs an API
key, and each key has its own rate limit.

```bash
kube-policy-mcp new-key alice >> keys
kube-policy-mcp serve --config kube-policy-mcp.yaml --http 127.0.0.1:8088 --keys keys
```

[docs/hosting.md](docs/hosting.md) has the systemd and Docker set-ups, and
the files are in [deploy](deploy).

## Engines

All three engines are built in by default. You can build a binary with only
the ones you use: an OPA-only binary is about 34 MB instead of 99 MB.

```bash
make build-opa
```

[docs/engines.md](docs/engines.md) covers single-engine builds and adding an
engine.

## Example policies

[examples/policies](examples/policies) is a working baseline that uses all
three engines.

| Requirement | Policy |
| --- | --- |
| Ownership labels | `opa/kubernetes.required_owner_labels` |
| Resource requests and limits | `opa/kubernetes.resource_limits`, `gatekeeper/K8sRequiredLimits/require-memory-limits` |
| No privileged containers | `vap/disallow-privileged-containers` |
| Approved registries | `opa/kubernetes.approved_registries` |
| No host networking | `vap/disallow-host-namespaces` |
| Health probes | `opa/kubernetes.health_probes` |
| Run as non-root | `vap/require-run-as-non-root` |
| Restricted namespaces | `opa/kubernetes.restricted_namespaces` |
| Workload labels (warning only) | `opa/kubernetes.workload_labels` |
| No hostPath volumes | `gatekeeper/K8sDisallowHostPath/restrict-hostpath-volumes` |

The `production` pack adds three policies that need context: a minimum
replica count, no `latest` tag, and a registered team label.

[examples/manifests](examples/manifests) has manifests that pass, fail, are
exempted, and need context.

## Security

- No cluster client is in the evaluation path.
- MCP arguments are never passed to a shell.
- Files are read only inside the workspace roots. Symlinks are resolved
  before that check.
- Policy sources come only from the config file.
- Policies cannot reach the network. Rego builtins such as `http.send` are
  removed, and a policy that needs the network or a live cluster is not run.
  It is reported as `error` or `unknown`.
- Input size, file counts and evaluation time are bounded.
- Values of `Secret` resources are removed from messages and explanations.
- An engine failure, timeout or panic becomes an `error` finding.
- In hosted mode, API keys are stored only as SHA-256 hashes.

## Limitations

- Mutation is not simulated. Policies see the manifest as written, without
  defaults or changes a cluster would add.
- A `ValidatingAdmissionPolicy` that matches only pods does not apply to
  Deployments. The policy has to match the controllers itself.
- A policy and its binding, or a constraint and its template, must be in the
  same source directory.
- Gatekeeper templates that read `data.inventory` need `context.resources`.
- A Rego policy applies to every kind unless it declares `custom.kinds` or an
  `applies` rule.

[docs/architecture.md](docs/architecture.md#known-offline-limitations) has
the full list.

## Documentation

| Page | Covers |
| --- | --- |
| [evaluation.md](docs/evaluation.md) | Results, selecting policies, context |
| [configuration.md](docs/configuration.md) | Config file, packs, exemptions, limits |
| [policy-authoring.md](docs/policy-authoring.md) | Writing policies for each engine |
| [hosting.md](docs/hosting.md) | HTTP mode, API keys, systemd, Docker |
| [engines.md](docs/engines.md) | Single-engine builds, adding an engine |
| [agent-workflow.md](docs/agent-workflow.md) | The agent loop, with real output |
| [architecture.md](docs/architecture.md) | Design, libraries, limitations |

## Development

```bash
make test
make vet
```

The tests in [tests](tests) build the binary and drive it over MCP, the way a
client does. CI runs the same checks on every push and pull request, and
publishes the container image from `master`.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The licences of the open source modules built into the program are in
`/licenses` in the container image. `make licenses` produces the same set
for a binary you built yourself.

This project is not affiliated with or endorsed by the Kubernetes, Open
Policy Agent or Gatekeeper projects.
