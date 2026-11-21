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

- Runs **locally** over stdio, or **hosted** over HTTP with an API key per
  caller. See [Host it](#host-it).
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

To use a hosted server instead, see [Host it](#host-it).

### Tools

| Tool | What it does |
| --- | --- |
| `list_policy_packs` | Lists the configured packs, the default pack, and the engines in this server. Pass `includeLimitations: true` to also get each engine's offline limitations. |
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

## Host it

One copy of the server can serve many agents over HTTP. With `--http`, it
serves MCP at `/mcp`. It only answers callers who send an API key, and each
key has its own rate limit.

```bash
kube-policy-mcp serve --config /etc/kube-policy-mcp/kube-policy-mcp.yaml --http 127.0.0.1:8088 --keys /etc/kube-policy-mcp/keys
```

### API keys

Make a key for each person or team:

```bash
sudo sh -c 'kube-policy-mcp new-key alice >> /etc/kube-policy-mcp/keys'
```

This prints the key once, for you to pass on, and adds a line to the keys
file. The file holds a name and the SHA-256 of each key, never the key
itself, so a lost key can't be recovered: make a new one.

```text
# /etc/kube-policy-mcp/keys
alice 5f2b…e91c
ci-pipeline 9a40…77d2
```

To revoke a key, delete its line. The server notices changes to the file
within a few seconds, with no restart. If an edit leaves the file broken, it
keeps using the keys it had and logs why.

### Rate limits

Each key may make 60 requests a minute, and up to 30 at once before that rate
applies. Change this with `--rate` and `--burst`. One key's use doesn't
affect another's. Requests without a valid key get `401`, and requests over
the limit get `429` with a `Retry-After` header.

### Set it up

The files in [deploy](deploy) set it up as a systemd service behind Apache.
Everything the server needs lives in one directory:

```text
/etc/kube-policy-mcp/kube-policy-mcp.yaml   the config (start from deploy/kube-policy-mcp.yaml)
/etc/kube-policy-mcp/policies/              your policy sources
/etc/kube-policy-mcp/keys                   the API keys
```

```sh
CGO_ENABLED=0 go build -trimpath -o kube-policy-mcp ./cmd/kube-policy-mcp   # on any machine
sudo install -m 755 kube-policy-mcp /usr/local/bin/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin kube-policy-mcp
sudo install -d -m 750 -o root -g kube-policy-mcp /etc/kube-policy-mcp
sudo install -m 640 -o root -g kube-policy-mcp deploy/kube-policy-mcp.yaml /etc/kube-policy-mcp/
sudo cp -r examples/policies /etc/kube-policy-mcp/policies            # or your own policies
sudo chgrp -R kube-policy-mcp /etc/kube-policy-mcp/policies
sudo install -m 640 -o root -g kube-policy-mcp /dev/null /etc/kube-policy-mcp/keys
sudo install -m 644 deploy/kube-policy-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now kube-policy-mcp
curl http://127.0.0.1:8088/healthz                  # prints ok
```

Then route `/mcp` to it from Apache. Copy `deploy/kube-policy-mcp-apache.conf`
to `/etc/apache2/` and include it in the site's HTTPS `<VirtualHost>`:

```sh
sudo a2enmod proxy proxy_http
sudo apachectl configtest && sudo systemctl reload apache2
```

The hosted config in `deploy/` has no `workspaceRoots`, so callers send
their manifests inline and cannot read files from the server.

### Or set it up with Docker

The [Dockerfile](Dockerfile) builds an image that holds the one program and
nothing else, and runs as an unprivileged user (ID 65532). There is no
published image yet, so the compose file builds it from this checkout.

Make the config directory, readable by that user, then start it with the
compose file from `deploy/`:

```sh
sudo install -d -m 750 -o root -g 65532 /etc/kube-policy-mcp
sudo install -m 640 -o root -g 65532 deploy/kube-policy-mcp.yaml /etc/kube-policy-mcp/
sudo cp -r examples/policies /etc/kube-policy-mcp/policies            # or your own policies
sudo chgrp -R 65532 /etc/kube-policy-mcp/policies
sudo install -m 640 -o root -g 65532 /dev/null /etc/kube-policy-mcp/keys
docker compose -f deploy/compose.yaml up -d --build
curl http://127.0.0.1:8088/healthz                  # prints ok
```

The compose file mounts the config directory read-only, runs the container
with a read-only file system and no capabilities, and publishes the port on
localhost only. Route `/mcp` to it from Apache as above.

Make keys with the image too. The key is printed for you; the line for the
file goes to standard output:

```sh
sudo sh -c 'docker run --rm kube-policy-mcp:local new-key alice >> /etc/kube-policy-mcp/keys'
```

To update, rebuild and start again. Nothing is lost that matters: only the
short history used by `explain_violation`.

```sh
git pull && docker compose -f deploy/compose.yaml up -d --build
```

To build the image yourself, with a version, or with fewer engines for a
smaller image:

```sh
docker build --build-arg VERSION=1.2.3 -t kube-policy-mcp:local .
```

```sh
docker build --build-arg TAGS="no_vap no_gatekeeper" -t kube-policy-mcp:opa .
```

**Podman** works too. The image and the compose file run unchanged with
`podman` and `podman-compose`. Two things differ:

- Run as root (`sudo podman …`), the config directory is set up exactly as
  above.
- Run rootless, user IDs inside the container are shifted, so ID 65532 can't
  read a file that only your own user can. Map the container's user onto
  yours with `--userns=keep-id:uid=65532,gid=65532` (in compose:
  `userns_mode: "keep-id:uid=65532,gid=65532"`), and have your own user own
  the config directory.

On a host with SELinux (Fedora, RHEL), add `,z` to the volume line, as in
`/etc/kube-policy-mcp:/config:ro,z`.

The image also works for the local mode, with no Go needed. Mount a
directory that holds your config and policies at `/config`:

```json
{
  "mcpServers": {
    "kube-policy": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-v", "/etc/kube-policy-mcp:/config:ro", "kube-policy-mcp:local"]
    }
  }
}
```

### Connecting an agent

```bash
claude mcp add --transport http kube-policy https://example.com/mcp --header "Authorization: Bearer <key>"
```

Or in `.mcp.json`:

```json
{
  "mcpServers": {
    "kube-policy": {
      "type": "http",
      "url": "https://example.com/mcp",
      "headers": {"Authorization": "Bearer <key>"}
    }
  }
}
```

### Things to know

- **Serve it over HTTPS only.** The key travels in a header on every request.
  Listen on `127.0.0.1` and put a reverse proxy with TLS in front.
- `/healthz` needs no key. `kube-policy-mcp check-health http://127.0.0.1:8088/healthz`
  exits 0 when the server is up; use it for container health checks.
- The server logs one line per request: the key's name, the status and the
  time taken. It never logs the request body.
- Each key holder only sees their own evaluations. `explain_violation` cannot
  be used to read a finding from another holder's evaluation.
- Callers normally send manifests inline. The `files` and
  `evaluate_directory` inputs read from the **server's** workspace roots, so
  leave `workspaceRoots` out of the config unless you want callers to read
  those directories.
- Every call stands alone (stateless HTTP), so the server can sit behind a
  proxy or a load balancer. The history for `explain_violation` is kept in
  memory per process, so with several copies an explanation may need the
  evaluation to be run again.

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
kube-policy-mcp serve --http 127.0.0.1:8088 --keys ./keys
kube-policy-mcp new-key alice >> ./keys
kube-policy-mcp check-health http://127.0.0.1:8088/healthz
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
- Hosted mode needs an API key on every request. Keys are stored only as
  SHA-256 hashes, and each key is rate limited.
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
