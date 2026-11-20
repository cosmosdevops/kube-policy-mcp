# Architecture

This document records the design: which upstream libraries are used, how the
parts fit together, and what cannot be reproduced offline.

## Goals

1. Let an agent find out whether its manifests comply with a set of
   organisational policies, with no cluster.
2. Use the real policy engines. No home-grown Rego or CEL interpreter, and
   no re-implementation of admission matching.
3. Never report compliance that was not actually established.

Schema validation is out of scope. Manifests are parsed only far enough to
read `apiVersion`, `kind`, name and namespace, and to hand the object to the
engines.

## Selected libraries

| Purpose | Library | Version | Notes |
| --- | --- | --- | --- |
| MCP server and client | `github.com/modelcontextprotocol/go-sdk` | v1.8.0 | Official Go SDK. stdio transport. Tool schemas are generated from Go types. |
| Rego evaluation | `github.com/open-policy-agent/opa/v1` | v1.22.4 | `ast` for parsing and compiling, `rego` for evaluation, `storage/inmem` for data. |
| ValidatingAdmissionPolicy | `k8s.io/apiserver` | v0.36.6 | The API server's own admission code: `admission/plugin/policy/validating` (validator), `policy/generic` and `policy/matching` (match logic), `plugin/cel` (compilation). |
| Gatekeeper | `github.com/open-policy-agent/gatekeeper/v3` and `frameworks/constraint` | v3.23.1 | The constraint client with the Rego and Kubernetes CEL drivers, the Kubernetes target (matching), expansion and the namespace excluder. The same code the webhook and `gator` run. |
| YAML/JSON | `k8s.io/apimachinery`, `sigs.k8s.io/yaml` | v0.36.6 | Document splitting and decoding. |
| CLI | `github.com/spf13/cobra` | v1.10.2 | |

Decisions worth knowing about:

- **Conftest is not imported.** Its conventions are followed (the resource is
  `input`; `deny`, `violation` and `warn` rules), but the adapter calls the
  OPA libraries directly. That gives control over capabilities, strict
  errors and per-policy results.
- **Admission policies are evaluated with the API server's code, not as bare
  CEL.** Matching, match conditions, variables, parameters, message
  expressions, audit annotations and the CEL cost budget all behave as in a
  cluster. The adapter calls the validator directly instead of the plugin's
  dispatcher, because the dispatcher folds everything into one allow or deny
  and the per-validation detail would be lost.
- **Gatekeeper constraints are not flattened into plain Rego.** Matching,
  parameters, enforcement actions and expansion belong to the constraint
  framework, so the adapter uses the framework, as `gator` does.
- **The Kubernetes libraries follow Gatekeeper.** Gatekeeper v3.23 builds
  against Kubernetes v0.36, so `k8s.io/*` is held at v0.36.x. The
  ValidatingAdmissionPolicy adapter shares those modules.
- **Everything is embedded.** The server is one static binary. No engine is
  shelled out to.

## Components

```text
cmd/kube-policy-mcp        main: runs the CLI
internal/cli               cobra commands (serve, evaluate, packs, policies, policy)
internal/mcpserver         MCP tools; no policy logic
internal/app               wires config, registered engines, pack registry, evaluator
internal/engines           engine plug-in registry (adapters register themselves)
internal/engines/builtin   links the adapters in; one build-tagged file per engine
internal/policy/enginetest contract tests every adapter must pass
internal/config            config file model and validation
internal/packs             pack resolution, precedence, source cache
internal/policy            Policy metadata model and the Engine interface
internal/engines/opa       OPA/Rego adapter
internal/engines/vap       Kubernetes ValidatingAdmissionPolicy adapter
internal/engines/gatekeeper  OPA Gatekeeper adapter
internal/evalctx           simulated evaluation context
internal/manifests         manifest parsing, workspace file access, redaction
internal/evaluator         orchestration, normalisation, exemptions, explain
internal/remediation       deterministic remediation text
internal/findings          the common result model
```

`internal/evaluator` and everything below it know nothing about MCP. The CLI
and the MCP server are two thin front ends over the same `app.App`.

Nothing outside `internal/engines/<name>` and `internal/engines/builtin`
refers to a specific engine. Adapters register themselves, and the set of
engines in a binary is chosen with build tags. See [engines.md](engines.md).

```text
MCP client / CLI
      |
  mcpserver / cli            parse input, enforce workspace and size limits
      |
  evaluator.Evaluate
      |-- packs.Registry.Resolve      pack -> ordered, de-duplicated policies
      |-- per engine, with timeout:   Engine.Evaluate(resources, policies, context)
      |-- coverage check              every (policy, resource) must have a result
      |-- required-context check      verdicts without needed context -> unknown
      |-- pack exemptions             fail/warning -> exempted
      |-- remediation, redaction, ordering, ids
      |
  findings.Report
```

## The engine interface

```go
type Engine interface {
    Name() string
    SupportedPolicyTypes() []string
    LoadSource(ctx context.Context, path string, lim Limits) (LoadResult, error)
    ValidatePolicy(ctx context.Context, p Policy) error
    Evaluate(ctx context.Context, resources []manifests.Resource,
        policies []Policy, ec evalctx.Context) ([]findings.Finding, error)
}
```

This is the interface from the brief with one addition, `LoadSource`: each
engine discovers its own native policy files and returns engine-neutral
`Policy` metadata. Engine-private state (compiled modules, typed policy
objects) travels in `Policy.Native`.

Adapters describe themselves through `engines.Registration` (title,
description, source format, limitations, upstream module). The MCP server
instructions, `list_policy_packs` and the `engines` command are generated
from those, so the core never names an engine.

The contract for `Evaluate`: return at least one finding for **every**
(policy, resource) pair. Use `not_applicable`, `unknown` or `error` when a
verdict is not possible. The evaluator checks this and turns any missing pair
into an `error`.

## Status model

`pass`, `fail`, `warning`, `not_applicable`, `exempted`, `unknown`, `error`.

- The verdict (`status`) and completeness (`complete`) are separate fields.
- `unknown` and `error` both make the report incomplete. An incomplete report
  is never `compliant`.
- Enforcement is normalised to `deny`, `warn` or `audit`. A violated `warn`
  or `audit` rule is a `warning`.

## How "never a false pass" is enforced

| Situation | Result |
| --- | --- |
| Policy file does not parse or compile | Policy stays in the list, marked with the problem; evaluation gives `error`. |
| Engine returns an error, panics or times out | `error` for every pair of that engine. |
| Engine returns nothing for a pair | `error`. |
| Engine returns a status the core does not know | `error`. |
| Rego builtin fails at run time | `error` (strict builtin errors are on). |
| Policy declares required context that is missing | `unknown`, replacing `pass`, `fail`, `warning`, and also `not_applicable` when the kind matches. |
| A policy, binding or constraint has a namespace selector and the namespace labels are unknown | `unknown`. |
| Admission policy reads `namespaceObject` and the namespace labels are unknown | `unknown`. |
| A binding passes a parameter object that was not supplied | `unknown`, whatever `parameterNotFoundAction` says. |
| A CEL expression fails at run time | `error`, even with `failurePolicy: Ignore`. |
| `ValidatingAdmissionPolicy` has no binding | `unknown`: the policy is not enforced and that is probably a mistake. |
| Gatekeeper template reads `data.inventory` and `context.resources` is empty | `unknown`. |
| Policy type cannot run offline | `unknown` for kinds it may apply to. |
| Pack has no policies | The request is refused. |
| Pack needs an engine that is not built in or is turned off | The whole pack is refused. It is never evaluated with only some of its policies. |
| Adapter returns a policy with a foreign or duplicate id | The source is refused. |
| Exemption matches an `unknown` or `error` | Left as it is. |

## OPA/Rego adapter

- A **policy** is a Rego package that defines `deny`, `violation`, `warn` or
  `unknown`. Packages without those rules are helper libraries.
- Each source directory (or `.tar.gz` bundle) is one compile unit. `data.json`
  and `data.yaml` files are loaded as data at the path given by their
  directory, as in an OPA bundle.
- Files are parsed as Rego v1 first, then as v0, so older policies still load.
- Metadata comes from OPA `# METADATA` annotations (see
  [policy-authoring.md](policy-authoring.md)).
- The resource is `input`. The context is under `data.kubepolicy`.
- Capabilities remove `http.send`, `net.lookup_ip_addr` and `opa.runtime`,
  and the network allow-list is empty.
- Applicability: `custom.kinds`, plus an optional boolean `applies` rule.

## ValidatingAdmissionPolicy adapter

- Loads `ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding`
  with strict decoding (unknown fields are errors). Every expression is
  compiled at load time. Any other object in the source is kept as a possible
  parameter.
- A **policy** is one `ValidatingAdmissionPolicy` together with the bindings
  that refer to it. It is evaluated once per binding that selects the
  resource, and once per parameter object the binding passes.
- The API server's defaults are applied before matching: an unset selector
  means "everything", `matchPolicy` is `Equivalent`, rule scope is `*`.
- For each resource the adapter builds admission attributes (operation, user,
  object, old object) and calls the upstream matcher and validator.
- Parameters (`paramKind` and `paramRef`) are looked up in the submitted
  manifests, `context.resources` and the policy source, in that order.
- Result mapping:
  - policy match constraints do not select the resource: `not_applicable`
  - no binding selects it, or the match conditions do not hold: `not_applicable`
  - every validation admits: `pass`
  - a validation denies: `fail` if the binding has `Deny`, else `warning`
  - evaluation error: `error`
- **Every failing validation is reported**, each with the rule id
  `validations[<index>]`.
- Audit annotations named `field`, `remediation`, `field.<index>` or
  `remediation.<index>` are copied into the findings.

## Gatekeeper adapter

- Loads `ConstraintTemplate`, constraints, `ExpansionTemplate`, mutators and
  `Config`. Templates and constraints are validated by adding them to a
  constraint client, which compiles the template code and checks each
  constraint against its template's parameter schema.
- A **policy** is one constraint. Its definition includes its template.
- Each source gets its own constraint client, with the Kubernetes CEL driver
  first and the Rego driver second, as in Gatekeeper. Reviews use the
  admission enforcement point (`validation.gatekeeper.sh`).
- The submitted manifests, `context.resources` and the known namespaces are
  added as data, so templates can read them through `data.inventory`.
- With `ExpansionTemplate` resources in the source, each resource is also
  expanded and the generated resources are reviewed, as `gator` does.
- Result mapping:
  - the constraint's match does not select the resource: `not_applicable`
  - the constraint has no action for admission (scoped actions): `not_applicable`
  - no violation: `pass`
  - violation: `fail` for `deny`, `warning` for `warn` and `dryrun`
  - the namespace is excluded by a `Config` resource: `exempted`
- Every violation is reported. A violation's `details.field` and
  `details.remediation` are copied into the finding.

## Known offline limitations

General:

- The context is whatever the caller says. Nothing is verified.
- Mutating admission is not simulated. Policies see the manifest as written,
  not as it would look after mutating webhooks, defaulting or other policies.
- Server-side defaulting is not applied. A field you leave out is absent,
  even where the API server would fill in a default.
- Namespace existence, quotas, RBAC and other cluster state are unknown.
- `context.kubernetesVersion` is passed to Rego only. It does not change how
  the admission engines evaluate.
- The plural resource name is guessed from the kind, because there is no API
  discovery. Custom resources with irregular plurals may not match a
  `resourceRules` entry; the result is then `not_applicable`.
- `UPDATE` uses the same object as old and new. `DELETE` passes it as the old
  object. Sub-resources are not simulated.

ValidatingAdmissionPolicy:

- There is no autogen. A policy that matches only pods does not apply to
  Deployments. Policies must match pod controllers themselves.
- Policies that use the `authorizer` variable are not run (`unknown`).
- Expressions are compiled without resource schemas, as when the API server
  has no type information. A wrong field name is an error at evaluation, not
  at load.
- `matchPolicy: Equivalent` cannot find equivalent resources in other API
  versions, because there is no API discovery.
- `MutatingAdmissionPolicy` is reported as unsupported (`unknown`).
- A policy and its bindings must be in the same source.

Gatekeeper:

- A constraint and its template must be in the same source.
- Templates that call `external_data` are not run (`unknown`).
- Mutators are only applied to resources generated by expansion.
- Only admission is simulated. Audit-only scoped actions give `not_applicable`.
- `SyncSet`, `GVKManifest` and provider resources are ignored with a warning.

OPA:

- Rego cannot be asked whether a policy "applied". Without `custom.kinds` or
  an `applies` rule, a policy that produces no violation is a `pass`.
- There are no native exceptions; use pack exemptions.

## Planned extensions (not implemented)

These are deliberately not built yet.

### Cluster policy discovery and snapshots

A read-only `discover` command and a `discover_cluster_policies` tool.

- Uses an explicitly named kubeconfig and context. Only `get` and `list`.
- Collects VAPs and bindings (and their
  parameter objects), Gatekeeper templates and constraints, and namespace
  labels.
- Writes a snapshot directory that is a normal policy source plus a
  `snapshot.yaml` with the cluster identity, retrieval time, resource
  versions and what was collected.
- Evaluations against a snapshot add a note with its age. A snapshot is a
  record of one moment, not live enforcement. Things that cannot be captured
  (webhook configuration, mutating policies, external data, later changes)
  are listed in the snapshot.

### Others

- `compare_policy_packs`: run one request against two packs and diff the findings.
- `test_policy`: evaluate a proposed policy against positive and negative fixtures.
- Remote policy distribution: fetch signed bundles ahead of time into a local
  directory; evaluation stays offline.
- HTTP transport for shared deployments.
