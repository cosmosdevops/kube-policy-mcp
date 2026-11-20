# Architecture

This document records the design: which upstream libraries are used, how the
parts fit together, and what cannot be reproduced offline.

## Goals

1. Let an agent find out whether its manifests comply with a set of
   organisational policies, with no cluster.
2. Use the real policy engines. No home-grown Rego or Kyverno interpreter.
3. Never report compliance that was not actually established.

Schema validation is out of scope. Manifests are parsed only far enough to
read `apiVersion`, `kind`, name and namespace, and to hand the object to the
engines.

## Selected libraries

| Purpose | Library | Version | Notes |
| --- | --- | --- | --- |
| MCP server and client | `github.com/modelcontextprotocol/go-sdk` | v1.8.0 | Official Go SDK. stdio transport. Tool schemas are generated from Go types. |
| Rego evaluation | `github.com/open-policy-agent/opa/v1` | v1.20.2 | `ast` for parsing and compiling, `rego` for evaluation, `storage/inmem` for data. |
| Kyverno evaluation | `github.com/kyverno/kyverno` | v1.20.0 | The CEL policy engine (`pkg/cel/policies/vpol`), the same code the Kyverno CLI and admission controller run. |
| YAML/JSON | `k8s.io/apimachinery`, `sigs.k8s.io/yaml` | from Kyverno | Document splitting and decoding. |
| CLI | `github.com/spf13/cobra` | v1.10.2 | |

Decisions worth knowing about:

- **OPA is pinned to v1.20.2, not the newest release.** OPA 1.21 and later
  need `gobwas/glob` v1, and Kyverno 1.20 only builds with v0.2. One binary
  can hold only one of them.
- **Conftest is not imported.** Its conventions are followed (the resource is
  `input`; `deny`, `violation` and `warn` rules), but the adapter calls the
  OPA libraries directly. That gives control over capabilities, strict
  errors and per-policy results.
- **Kyverno is embedded, not shelled out to.** The server is one static
  binary and gets structured rule responses instead of parsing CLI text.
  The cost is a large dependency tree and two `replace` lines in `go.mod`
  that mirror Kyverno's own.
- **Kyverno 1.20 removed the legacy `kyverno.io` policy kinds**
  (`ClusterPolicy`, `Policy`). The maintained format is the CEL-based
  `policies.kyverno.io` `ValidatingPolicy`, so that is what the adapter
  supports. Legacy files are detected and reported as unsupported.

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
internal/engines/kyverno   Kyverno adapter
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
| Kyverno policy has a namespace selector and the namespace labels are unknown | `unknown`. |
| Kyverno policy reads `namespaceObject` and the namespace is unknown | `unknown`. |
| Kyverno policy looks up a resource that was not supplied | `unknown`. |
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

## Kyverno adapter

- Loads `ValidatingPolicy`, `NamespacedValidatingPolicy` and `PolicyException`
  with strict decoding (unknown fields are errors) and compiles each policy at
  load time.
- For each resource it builds an admission request (operation, user, object,
  old object) and calls the upstream engine. Matching, match conditions,
  variables, autogen for pod controllers and exceptions are all upstream code.
- `resource.Get` and `resource.List` are served from the submitted manifests
  and `context.resources` only. `globalContext` is served from `context.data`.
- Result mapping:
  - no rule response: `not_applicable` (or `unknown`, see the table above)
  - rule `pass`: `pass`
  - rule `fail`: `fail` if `validationActions` contains `Deny`, else `warning`
  - rule skipped by an exception: `exempted`
  - rule skipped by match conditions: `not_applicable`
  - rule `error`: `unknown` when it is a context problem, else `error`
- Rule ids are `validations[<index>]`, taken from the engine response.

## Known offline limitations

General:

- The context is whatever the caller says. Nothing is verified.
- Mutating admission is not simulated. Policies see the manifest as written,
  not as it would look after mutating webhooks, defaulting or other policies.
- Server-side defaulting is not applied. A field you leave out is absent,
  even where the API server would fill in a default.
- Namespace existence, quotas, RBAC and other cluster state are unknown.
- `context.kubernetesVersion` is passed to Rego only. It does not change how
  Kyverno evaluates.

Kyverno:

- Only CEL `ValidatingPolicy` kinds are evaluated. Mutating, generating,
  deleting and image-validating policies, JSON/Envoy/HTTP evaluation modes
  and legacy `kyverno.io` kinds are reported as unsupported (`unknown`).
- Policies using the `http` library, `image.GetMetadata`, `resource.Post` or
  `resource.ToGVR` are not run.
- The plural resource name is guessed from the kind, because there is no API
  discovery. Custom resources with irregular plurals may not match
  `resourceRules`; the result is then `not_applicable`.
- `UPDATE` uses the same object as old and new. `DELETE` passes it as the old
  object. Sub-resources are not simulated.
- Kyverno reports the first failing validation of a policy, not all of them.
- Background-scan behaviour is not simulated; evaluation is always the
  admission path.
- A `PolicyException` is matched by its `policyRefs` and `matchConditions`.
  The exception's own namespace does not limit it, which is upstream
  behaviour for the offline engine.

OPA:

- Rego cannot be asked whether a policy "applied". Without `custom.kinds` or
  an `applies` rule, a policy that produces no violation is a `pass`.
- There are no native exceptions; use pack exemptions.

## Planned extensions (not implemented)

These fit behind the same `Engine` interface. They are deliberately not
built yet. Each would be a new adapter package plus one line in
`internal/engines/builtin`; see [engines.md](engines.md#adding-an-engine).

### Kubernetes CEL admission policies

`ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding`.

- A policy without a binding does nothing in a cluster. The adapter must
  model bindings: `matchResources`, `paramRef` (including the
  `parameterNotFoundAction`), and `validationActions` on the binding, which
  is where `Deny`, `Warn` and `Audit` live.
- Parameters are context: a `paramRef` to an object that was not supplied
  must give `unknown`.
- Use `k8s.io/apiserver/pkg/admission/plugin/policy/validating` for
  compilation and evaluation, so that variables, `matchConditions`,
  `auditAnnotations`, `failurePolicy` and the CEL cost budget behave as in
  the API server. Evaluating a bare CEL expression is not equivalent.
- CEL type checking needs OpenAPI schemas. Offline that means built-in
  schemas for a chosen Kubernetes version and declared CRD schemas.
- Kyverno already wraps this in `pkg/admissionpolicy`. It is not used today
  because that wrapper logs and skips binding and evaluation errors, which
  could hide a failure. A dedicated `engines/cel` adapter should call the
  apiserver packages directly. Until then VAP files are reported as
  unsupported.

### Gatekeeper

`ConstraintTemplate` and constraints.

- Use the Open Policy Agent `frameworks/constraint` client with the Rego (and
  K8s CEL) drivers, as `gator` does. Do not flatten constraints into plain
  Conftest policies: matching (`kinds`, `namespaces`, `namespaceSelector`,
  `labelSelector`, `scope`), parameters and `enforcementAction` (`deny`,
  `warn`, `dryrun`, scoped actions) belong to the constraint.
- `data.inventory` (referential constraints) is context. Templates that read
  it need `context.resources`, or the result is `unknown`.
- Exemptions come from the Gatekeeper `Config` resource and
  `--exempt-namespace` settings, which must be part of the policy source.

### Cluster policy discovery and snapshots

A read-only `discover` command and a `discover_cluster_policies` tool.

- Uses an explicitly named kubeconfig and context. Only `get` and `list`.
- Collects Kyverno policies and exceptions, VAPs and bindings (and their
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
