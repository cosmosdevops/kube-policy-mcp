# Configuration

One YAML file defines the policy packs, the workspace and the limits.
[examples/kube-policy-mcp.yaml](../examples/kube-policy-mcp.yaml) is a
working one.

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

The file is looked for in this order: `--config`, `$KUBE_POLICY_MCP_CONFIG`,
then `./kube-policy-mcp.yaml`. Relative paths are resolved from the directory
of the config file.

Policy directories come only from this file, never from MCP arguments.
Listing a directory here is what approves it.

## Workspace roots

`workspaceRoots` are the only directories the `files` and
`evaluate_directory` inputs can read. `--workspace-root` adds more at start
up. With no roots, file access is off and callers must send manifests inline.

Symlinks are resolved before the check, so a link cannot point outside a
root.

## Limits

| Setting | Default | Bounds |
| --- | --- | --- |
| `evaluationTimeout` | 30s | One engine's run for one request. |
| `maxManifestBytes` | 5 MB | Manifest input per call. |
| `maxResources` | 500 | Resources per call. |
| `maxFiles` | 2000 | Files read by `evaluate_directory`. |
| `maxPolicyBytes` | 2 MB | One policy file. |
| `maxPolicyFiles` | 2000 | Files in one policy source. |

## Engines

| Engine | `engine:` | A source directory holds |
| --- | --- | --- |
| OPA / Rego | `opa` | `.rego` files following Conftest conventions (`deny`, `violation`, `warn`). |
| Kubernetes ValidatingAdmissionPolicy | `vap` | `ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding` resources, plus any parameter objects. |
| OPA Gatekeeper | `gatekeeper` | `ConstraintTemplate` resources and their constraints, plus optional `ExpansionTemplate` and `Config` resources. |

Turn an engine off with:

```yaml
engines:
  gatekeeper:
    enabled: false
```

A pack that needs an engine that is turned off, or not built in, is refused
as a whole. It is never evaluated with only part of its policies.
[engines.md](engines.md) covers single-engine builds.

## Policy ids

A policy's id is `<engine>/<native name>`:

- `opa/<rego package>`
- `vap/<policy name>`
- `gatekeeper/<constraint kind>/<constraint name>`

For the two admission engines, a policy is what is actually enforced. A
`ValidatingAdmissionPolicy` is evaluated through its bindings, and a
Gatekeeper constraint through its template. A policy with no binding is
reported as `unknown`. A template with no constraint is only a load warning.

## Packs and precedence

- `extends` is resolved depth-first, parents before children. Each pack is
  used once, at its first position. A cycle is an error.
- If two sources supply the same policy id, the one processed later wins. So
  a child pack overrides its parents, and a later source overrides an earlier
  one. Every override is listed in the result notes.
- The final list is sorted by id, so the result does not depend on file
  order.
- Each Rego source directory is compiled on its own. A Rego policy can import
  helper packages from the same source, but not from another.
- Policies are reloaded when a file in a source changes.

## Exemptions

A pack can exempt named resources from named policies. This works for every
engine.

```yaml
policyPacks:
  - name: platform-baseline
    exemptions:
      - name: node-exporter-host-access
        policies:
          - vap/disallow-host-namespaces
        resources:
          kinds: [DaemonSet]
          namespaces: [monitoring]
          names: [node-exporter]
        reason: node-exporter needs the host network to read node metrics.
        expires: "2027-06-30"   # optional
```

`policies`, `namespaces` and `names` accept `*` as a wildcard. `reason` is
required. After `expires`, the exemption is ignored and a note says so.

Gatekeeper also has its own mechanism: a `Config` resource in a Gatekeeper
source can exclude namespaces from admission (`spec.match`, process `webhook`
or `*`).

An exemption turns `fail` or `warning` into `exempted`. It never hides an
`unknown` or an `error`.
