# kube-policy-mcp

An MCP server that lets AI coding agents check Kubernetes manifests against
your organisation's policies **before** anything is deployed.

- Evaluates real **OPA/Rego**, **OPA Gatekeeper** and Kubernetes
  **ValidatingAdmissionPolicy** policies using the upstream engines.
- Works **offline**. It never talks to a cluster and never applies anything.
- Tells the agent *what* failed, *why*, and *how to fix it*, so the agent can
  correct its manifest and check again.
- Is honest about what it could not check. A policy that does not apply, could
  not be decided, or crashed is never reported as a pass.

- Engines are **plug-ins**. Build with all three, or with only the one you use
  (an OPA-only binary is about 34 MB instead of 99 MB).

It does **not** validate Kubernetes schemas. Use a schema validator
(for example with the KubernetesJSONSchema schemas) for that.

## Quick start

Requires Go 1.27 or newer.

```bash
make build
```

```bash
./bin/kube-policy-mcp evaluate --config examples/kube-policy-mcp.yaml --file examples/manifests/noncompliant/web.yaml
```

```bash
make demo
```

`make demo` starts the MCP server and runs the full agent workflow against it:
discover policies, evaluate a draft, read the findings, evaluate the fix.
See [docs/agent-workflow.md](docs/agent-workflow.md) for the output.

## Using it from an MCP client

The server speaks MCP over stdio:

```bash
kube-policy-mcp serve --config /path/to/kube-policy-mcp.yaml --workspace-root /path/to/project
```

**Claude Code** — add this to `.mcp.json` in your project
(see [examples/mcp/claude-code.mcp.json](examples/mcp/claude-code.mcp.json)):

```json
{
  "mcpServers": {
    "kube-policy": {
      "command": "/usr/local/bin/kube-policy-mcp",
      "args": ["serve", "--config", "/etc/kube-policy-mcp/kube-policy-mcp.yaml", "--workspace-root", "."]
    }
  }
}
```

Or register it from the command line:

```bash
claude mcp add kube-policy -- /usr/local/bin/kube-policy-mcp serve --config /etc/kube-policy-mcp/kube-policy-mcp.yaml --workspace-root .
```

Other MCP clients (Claude Desktop, Cursor, VS Code and so on) use the same
command and arguments; see [examples/mcp/generic-client.json](examples/mcp/generic-client.json).

### Tools

| Tool | What it does |
| --- | --- |
| `list_policy_packs` | Lists the configured packs, the default pack, and the engines in this server with their limitations. |
| `list_policies` | Lists the policies of a pack. Filter by engine, kind, severity or namespace. |
| `get_policy` | Shows one policy: purpose, rules, matching, enforcement, exceptions, required context, remediation. Can include the source. |
| `evaluate_manifests` | Evaluates inline YAML/JSON or workspace files against a pack. |
| `evaluate_directory` | Evaluates every manifest under a workspace directory, grouped by file and resource. |
| `explain_violation` | Explains a finding from an earlier evaluation: rule, expected behaviour, observed value, fix. |

### Reading a result

```json
{
  "status": "fail",
  "complete": true,
  "compliant": false,
  "policyPack": "platform-baseline",
  "summary": { "resourcesEvaluated": 1, "policiesEvaluated": 11, "violations": 15, "warnings": 3, "unknown": 0, "errors": 0, "exempted": 0, "passed": 0, "notApplicable": 0 },
  "findings": [
    {
      "id": "f-3fa9c21b-006",
      "engine": "opa",
      "policy": "opa/kubernetes.approved_registries",
      "rule": "deny",
      "resource": { "apiVersion": "apps/v1", "kind": "Deployment", "namespace": "default", "name": "web", "source": "inline#0" },
      "status": "fail",
      "severity": "high",
      "enforcement": "deny",
      "field": "spec.template.spec.containers[0].image",
      "message": "container \"web\" uses image \"nginx:latest\", which is not from an approved registry",
      "remediation": { "description": "Use an image from one of the approved registries listed in the policy data, or ask the platform team to mirror the image.", "source": "policy-metadata" }
    }
  ]
}
```

Each finding has one of seven statuses:

| Status | Meaning |
| --- | --- |
| `pass` | The policy applied and the resource complied. |
| `fail` | An enforced rule was violated. |
| `warning` | A warn-only or audit-only rule was violated. Does not block compliance. |
| `not_applicable` | The policy does not match this resource. Never counted as a pass. |
| `exempted` | An approved exception covers the resource. |
| `unknown` | Compliance could not be decided (missing context, or a check that cannot run offline). |
| `error` | The engine or the policy failed. Never counted as a pass. |

The verdict and the completeness are reported separately:

- `status` is `fail` if anything failed; otherwise `unknown` if anything is
  `unknown` or `error`; otherwise `warning` or `pass`.
- `complete` is `false` when any check ended as `unknown` or `error`.
- `compliant` is `true` only when nothing failed **and** the evaluation is complete.

By default `findings` lists only what needs attention. Pass
`options.includeAllResults: true` to also see `pass` and `not_applicable`.
`policyResults` always gives the per-policy counts.

## Configuration

One YAML file defines the policy packs, the workspace and the limits.
See [examples/kube-policy-mcp.yaml](examples/kube-policy-mcp.yaml).

```yaml
workspaceRoots:            # the only directories manifests may be read from
  - ./manifests
defaultPolicyPack: platform-baseline
limits:
  evaluationTimeout: 30s   # per engine, per request
policyPacks:
  - name: platform-baseline
    description: Enterprise Kubernetes baseline
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

The config file is found through `--config`, then `$KUBE_POLICY_MCP_CONFIG`,
then `./kube-policy-mcp.yaml`. Relative paths are resolved from the config
file's directory. Policy directories are only ever taken from this file,
never from MCP arguments, so listing a directory here is what approves it.

### Engines

Engines are self-contained adapters. See [docs/engines.md](docs/engines.md).

```bash
kube-policy-mcp engines
```

| Engine | `engine:` | A source directory holds |
| --- | --- | --- |
| OPA / Rego | `opa` | `.rego` files following Conftest conventions (`deny`, `violation`, `warn`). |
| Kubernetes ValidatingAdmissionPolicy | `vap` | `ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding` resources, plus any parameter objects. |
| OPA Gatekeeper | `gatekeeper` | `ConstraintTemplate` resources and their constraints, plus optional `ExpansionTemplate` and `Config` resources. |

- **Build time**: `make build` includes all three. `make build-opa`,
  `make build-vap` and `make build-gatekeeper` build a single-engine binary.
- **Run time**: turn an engine off in the config.

  ```yaml
  engines:
    gatekeeper:
      enabled: false
  ```

- A pack that needs an engine that is absent or turned off is refused as a
  whole. It is never evaluated with only part of its policies.

### Packs, identity and precedence

- A policy's id is `<engine>/<native name>`:
  - `opa/<rego package>`
  - `vap/<policy name>`
  - `gatekeeper/<constraint kind>/<constraint name>`
- For the two admission engines, a policy is what is actually enforced. A
  `ValidatingAdmissionPolicy` is evaluated through its bindings, and a
  Gatekeeper constraint through its template. A policy with no binding is
  reported as `unknown`; a template with no constraint is only a load warning.
- `extends` is resolved depth-first, parents before children. Each pack is
  used once, at its first position. A cycle is an error.
- If two sources supply the same policy id, the one processed **later** wins.
  So a child pack overrides its parents, and a later source overrides an
  earlier one. Every override is listed in the result notes.
- The final policy list is sorted by id, so resolution is deterministic.
- Each Rego source directory is compiled on its own. Rego policies can import
  helper packages from the same source, but not from another source.
- Policies are reloaded automatically when a file in a source changes.

### Exemptions

- **Gatekeeper**: a `Config` resource in a Gatekeeper source can exclude
  namespaces from admission (`spec.match`, process `webhook` or `*`).
- **Any engine**: pack-level `exemptions` in the config, selected by policy id
  and by resource kind, namespace and name (with `*` wildcards). They need a
  `reason` and may have an `expires` date.

An exemption turns `fail` or `warning` into `exempted`. It never hides an
`unknown` or an `error`.

## Evaluation context

A policy may need more than the manifest. Pass that as `context`. These are
values **you claim**, not facts read from a cluster.

```yaml
context:
  kubernetesVersion: "1.35"
  namespace:                 # the target namespace and its labels
    name: production
    labels: { environment: production, team: payments }
  operation: CREATE          # CREATE (default), UPDATE or DELETE
  user:
    username: developer@example.com
    groups: [developers]
  variables: { environment: production }
  resources:                 # other objects policies may look up
    - apiVersion: v1
      kind: ConfigMap
      metadata: { name: registered-teams, namespace: platform-system }
      data: { payments: "true" }
  data: { tier: gold }       # free-form policy data
```

If a policy needs context that was not supplied, its result is `unknown` and
the finding lists what is missing. Details:

- A namespace given by name only has **unknown** labels. Write `labels: {}`
  to state that it has none.
- A `Namespace` object included in the manifests or in `context.resources`
  counts as that namespace's metadata.
- Resources without `metadata.namespace` are evaluated as if deployed to
  `context.namespace.name`. Your manifests are never modified.

## CLI

The CLI uses the same core as the MCP server. It is meant for local testing,
debugging and CI.

```bash
kube-policy-mcp evaluate --file deployment.yaml --policy-pack platform-baseline
kube-policy-mcp evaluate --dir ./k8s --output json
kube-policy-mcp evaluate --file app.yaml --policy-pack production --context-file context.yaml --explain
cat app.yaml | kube-policy-mcp evaluate --file - --namespace payments
kube-policy-mcp packs
kube-policy-mcp engines
kube-policy-mcp policies --kind Deployment
kube-policy-mcp policy vap/require-run-as-non-root --definition
```

`evaluate` exit codes: `0` compliant, `1` violations, `2` incomplete
(nothing failed, but some checks are `unknown` or `error`), `3` usage or
runtime error.

## Example policy library

[examples/policies](examples/policies) holds a working baseline using real
Rego, ValidatingAdmissionPolicy and Gatekeeper policies.

| # | Requirement | Policy |
| --- | --- | --- |
| 1 | Required ownership labels | `opa/kubernetes.required_owner_labels` |
| 2 | Required resource requests and limits | `opa/kubernetes.resource_limits`, `gatekeeper/K8sRequiredLimits/require-memory-limits` |
| 3 | Restricted container privileges | `vap/disallow-privileged-containers` |
| 4 | Approved container registries | `opa/kubernetes.approved_registries` (list in `data.yaml`) |
| 5 | Prohibited host networking | `vap/disallow-host-namespaces` |
| 6 | Required health probes | `opa/kubernetes.health_probes` (readiness denies, liveness warns) |
| 7 | Non-root container execution | `vap/require-run-as-non-root` |
| 8 | Restricted namespaces | `opa/kubernetes.restricted_namespaces` |
| 9 | Required workload labels | `opa/kubernetes.workload_labels` (warn only) |
| 10 | Restrictions on hostPath volumes | `gatekeeper/K8sDisallowHostPath/restrict-hostpath-volumes` |

The `production` pack adds three context-dependent policies:
`opa/production.min_replicas` and
`gatekeeper/K8sDisallowedTags/disallow-latest-tag-in-production` (both need
namespace labels), and `vap/require-registered-team` (takes a ConfigMap as
its parameter).

The two admission engines cover pod controllers in different ways, and the
examples show both. The `vap` policies match Deployments and the other
controllers themselves and find the pod spec inside each kind. The Gatekeeper
constraints match Pods, and an `ExpansionTemplate` makes Gatekeeper also check
the Pod that a Deployment would create.

Fixtures in [examples/manifests](examples/manifests):

| Fixture | Shows |
| --- | --- |
| `compliant/web.yaml` | Passes. The Service is `not_applicable` for the pod policies. |
| `noncompliant/web.yaml` | Many policies from all three engines failing on one resource. |
| `multi/app.yaml` | Several resources in one file with different outcomes. |
| `exemptions/node-exporter.yaml` | Two pack exemptions being honoured. |
| `production/checkout.yaml` | `unknown` without context; passes with `production/context.yaml`. |

## Security

- Offline by default. There is no cluster client in the evaluation path.
- No shell execution. MCP arguments are never passed to a shell.
- Files are only read inside the workspace roots. Symlinks are resolved
  before the check, and directory walks do not follow them.
- Policy sources come only from the config file.
- Rego policies that use `http.send`, `net.lookup_ip_addr` or `opa.runtime`
  fail to compile, and the result is `error`.
- Gatekeeper templates run with the same builtins removed. Templates that
  call `external_data` are not run; the result is `unknown`.
- Admission policies that use the `authorizer` variable are not run; the
  result is `unknown`.
- Input sizes, file counts and evaluation time are bounded.
- Values of `Secret` resources are removed from messages and explanations.
- Engine failures, timeouts and panics become `error` findings.

## Limitations

Read [docs/architecture.md](docs/architecture.md#known-offline-limitations)
for the full list. The main ones:

- A `ValidatingAdmissionPolicy` has no autogen. A policy that matches only
  pods does not apply to Deployments. Match the controllers in the policy.
- A `ValidatingAdmissionPolicy` and its binding, or a Gatekeeper constraint
  and its template, must be in the same source directory.
- Gatekeeper templates that read `data.inventory` need `context.resources`.
  Without it the result is `unknown`.
- Mutation is not simulated. Policies see the manifest as written.
- Cluster policy discovery is designed but not implemented.
- Rego has no native notion of "this policy applies to that kind". Declare
  `custom.kinds` (or an `applies` rule) or the policy is treated as applying
  to everything.

## Documentation

- [docs/architecture.md](docs/architecture.md) — design, libraries, interfaces, limitations, planned extensions.
- [docs/engines.md](docs/engines.md) — how engines plug in, single-engine builds, adding an engine.
- [docs/policy-authoring.md](docs/policy-authoring.md) — how to write Rego, ValidatingAdmissionPolicy and Gatekeeper policies for this server.
- [docs/agent-workflow.md](docs/agent-workflow.md) — the end-to-end agent workflow with real output.

## Development

```bash
make test
```

```bash
make vet
```

The tests in [tests](tests) build the binary and drive it over MCP stdio,
the same way a client does.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
