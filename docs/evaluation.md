# Evaluating manifests

This page covers what a result looks like, how to check against only some
policies, and how to supply context.

## Reading a result

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
| `not_applicable` | The policy does not match this resource. Not counted as a pass. |
| `exempted` | An approved exception covers the resource. |
| `unknown` | Compliance could not be decided: context is missing, or the check cannot run offline. |
| `error` | The engine or the policy failed. Not counted as a pass. |

The verdict and its completeness are separate fields:

- `status` is `fail` if anything failed. Otherwise it is `unknown` if anything
  is `unknown` or `error`. Otherwise it is `warning` or `pass`.
- `complete` is `false` when any check ended as `unknown` or `error`.
- `compliant` is `true` only when nothing failed and the evaluation is
  complete.

`findings` lists only what needs attention. Pass
`options.includeAllResults: true` to also get `pass` and `not_applicable`.
`policyResults` always has the counts per policy.

Pass a finding's `id` to `explain_violation` for the rule, the expected
behaviour, the value that was found and the fix.

## Checking against some policies only

A manifest is checked against the whole pack unless you narrow it. Both
evaluation tools take three optional inputs, and the CLI has matching flags.

| Input | CLI flag | Selects | Example |
| --- | --- | --- | --- |
| `policies` | `--policy` | Policy ids. `*` is a wildcard. | `vap/disallow-host-namespaces`, `gatekeeper/*`, `*host*` |
| `engines` | `--engine` | Every policy of these engines. | `opa` |
| `severities` | `--severity` | Every policy with one of these severities. | `high` |

```json
{
  "name": "evaluate_manifests",
  "arguments": {
    "manifests": "...",
    "engines": ["opa", "vap"],
    "severities": ["high"]
  }
}
```

```bash
kube-policy-mcp evaluate --file app.yaml --engine opa --engine vap --severity high
```

- Within one input, entries add up: `["high", "critical"]` means either.
- Across inputs, all must hold. The call above checks policies from `opa` or
  `vap` that also have severity `high`.
- Anything that matches nothing is an error: an unknown id, a pattern with no
  match, an engine or severity no policy has, or inputs with no policy in
  common. A typing mistake cannot shrink the evaluation unnoticed.
- A narrowed result carries a note such as "Only 4 of the 11 policies in the
  pack were evaluated". `compliant` then covers those policies only.
- Severity is whatever each policy declares, and there is no ordering. A
  policy that declares none is not selected by `severities`.

## Context

A policy may depend on more than the manifest: the labels of the target
namespace, the user, another object in the cluster. Pass those as `context`.
They are values you state, not facts read from a cluster.

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

On the command line, put the same content in a file and pass
`--context-file`.

If a policy needs context that was not supplied, its result is `unknown` and
the finding lists what is missing.

- A namespace given by name only has unknown labels. Write `labels: {}` to
  state that it has none.
- A `Namespace` object in the manifests or in `context.resources` counts as
  that namespace's metadata.
- Resources without `metadata.namespace` are evaluated as if deployed to
  `context.namespace.name`. The manifests themselves are not changed.

[agent-workflow.md](agent-workflow.md) shows an evaluation that is `unknown`
without context and passes with it.
