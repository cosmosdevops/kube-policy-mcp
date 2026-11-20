# Policy engines are plug-ins

Each policy engine is a self-contained adapter. The core does not know which
engines exist. You can leave an engine out of a build, turn one off in the
config, or add a new one without touching the core.

## What is in a build

```bash
kube-policy-mcp engines
```

This lists the engines linked into the binary, the upstream version of each,
and their offline limitations. It needs no config file.

## Choosing engines at build time

| Command | Engines | Binary size |
| --- | --- | --- |
| `make build` | OPA, ValidatingAdmissionPolicy and Gatekeeper | about 99 MB |
| `make build-opa` | OPA only | about 34 MB |
| `make build-vap` | ValidatingAdmissionPolicy only | about 73 MB |
| `make build-gatekeeper` | Gatekeeper only | about 93 MB |

The size difference is real: an engine that is left out is not linked, and
neither are its dependencies. The OPA-only build contains no Kubernetes API
server or Gatekeeper code. The ValidatingAdmissionPolicy-only build contains
no OPA code.

Gatekeeper is the exception. It is built on OPA and on the Kubernetes API
server libraries, so a Gatekeeper-only build still links both. It just does
not offer the `opa` and `vap` engines.

The plain `go build` equivalents use build tags. There is one tag per
engine: `no_opa`, `no_vap` and `no_gatekeeper`.

```bash
go build -tags "no_vap no_gatekeeper" -o bin/kube-policy-mcp-opa ./cmd/kube-policy-mcp
```

```bash
go build -tags no_gatekeeper -o bin/kube-policy-mcp ./cmd/kube-policy-mcp
```

## Turning an engine off at run time

```yaml
engines:
  gatekeeper:
    enabled: false
```

An engine that is not mentioned is on. Turning off an engine that is not in
the build is harmless, so one config file can serve several builds. Naming an
engine that is not in the build without turning it off is an error.

## What happens to packs that need a missing engine

A pack with a source for an engine that is absent or turned off is **refused
as a whole**. It is not evaluated with the remaining engines.

That is deliberate. Dropping half a pack's policies quietly would make a
manifest look more compliant than it is. `list_policy_packs` and
`kube-policy-mcp packs` mark such packs with the reason, and evaluating one
returns an error that names the engine.

If you want an OPA-only setup, define packs that only have `opa` sources.

## How an adapter plugs in

```text
cmd/kube-policy-mcp/main.go
    imports  internal/engines/builtin        (blank import)

internal/engines/builtin/opa.go      //go:build !no_opa
    imports  internal/engines/opa            (blank import)
internal/engines/builtin/vap.go      //go:build !no_vap
    imports  internal/engines/vap            (blank import)
internal/engines/builtin/gatekeeper.go  //go:build !no_gatekeeper
    imports  internal/engines/gatekeeper     (blank import)

internal/engines/<name>/register.go
    func init() { engines.Register(engines.Registration{...}) }
```

- `internal/engines` is the registry. Adapters call `engines.Register` from
  an `init` function, the same pattern as `database/sql` drivers.
- `internal/engines/builtin` is the only place that names the adapters. It
  holds one small file per engine, each guarded by a build tag.
- `internal/app` asks the registry what is linked in, applies the config, and
  hands the active engines to the pack registry and the evaluator.

Nothing else refers to a specific engine: not the evaluator, the pack
registry, the MCP tools or the CLI. Text that names engines (the MCP server
instructions, `list_policy_packs`, the `engines` command) is generated from
the registrations.

## Adding an engine

1. Create `internal/engines/<name>/` and implement `policy.Engine`:

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

2. Register it in `internal/engines/<name>/register.go`:

   ```go
   const EngineName = "myengine"

   func init() {
       engines.Register(engines.Registration{
           Name:         EngineName,
           Title:        "My Engine",
           Description:  "One sentence on what the adapter evaluates.",
           SourceFormat: "What a policy source path must contain.",
           Limitations:  []string{"What it cannot do offline."},
           Module:       "example.com/upstream/myengine",
           New:          func() policy.Engine { return New() },
       })
   }
   ```

3. Add `internal/engines/builtin/<name>.go`:

   ```go
   //go:build !no_myengine

   package builtin

   import _ "github.com/cosmosdevops/kube-policy-mcp/internal/engines/myengine"
   ```

4. Add a contract test in the adapter package:

   ```go
   func TestEngineContract(t *testing.T) {
       enginetest.Run(t, New(), "path/to/example/policies", manifestYAML)
   }
   ```

That is all. Pack resolution, timeouts, exemptions, required-context checks,
remediation, redaction, the six MCP tools and the CLI work for the new engine
without changes. Use it in the config with `engine: myengine`.

The three built-in adapters are the reference: `opa` is the smallest,
`vap` shows policies that need a second object (the binding) to take
effect, and `gatekeeper` shows one policy per constraint with a shared
template.

## The adapter contract

`internal/policy/enginetest` checks these rules, and the core enforces the
important ones again at run time.

Loading:

- A missing source is an error, not an empty list.
- Policies come back sorted by id, and loading twice gives the same result.
- Each policy has `Engine` set to the engine name and an id that starts with
  `<engine>/`. Ids are unique within a source. (Enforced at run time.)
- A policy that cannot be evaluated stays in the list with `Supported: false`
  and a `Problem`. It is never dropped.

Evaluating:

- There is at least one finding for every (policy, resource) pair.
  (Enforced at run time: a missing pair becomes an `error`.)
- Only the seven known statuses are used. (Enforced at run time.)
- A policy that cannot be evaluated never produces `pass`, `fail`, `warning`
  or `exempted`.
- `fail`, `warning`, `unknown` and `error` findings carry a message.
  `exempted` findings name the exception.
- The submitted resources are not modified.
- The same input gives the same output.
- Only the policies passed in are reported on.

What an adapter does **not** need to do, because the core does it:

- Enforce the evaluation timeout or recover from its own panics.
- Check `Policy.RequiredContext` against the supplied context.
- Apply pack-level exemptions.
- Attach remediation text from policy metadata.
- Redact secret values or bound message length.
- Assign finding ids or sort the results.

## Limits of the modularity

- **One Go module.** All adapters share one `go.mod`, so dependency versions
  must be compatible across engines even in a single-engine build. Today
  that means the Kubernetes libraries stay at the version Gatekeeper builds
  against (v0.36.x), also for the ValidatingAdmissionPolicy adapter.
- **Compile-time plug-ins only.** Adapters are Go packages linked into the
  binary. There is no loading of engines from separate files at run time.
- **The example library uses all three engines.** The example packs mix
  OPA, ValidatingAdmissionPolicy and Gatekeeper sources, so they only work in
  the full build.
