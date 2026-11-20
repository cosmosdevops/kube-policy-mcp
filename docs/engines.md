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
| `make build` | OPA and Kyverno | about 129 MB |
| `make build-opa` | OPA only | about 36 MB |
| `make build-kyverno` | Kyverno only | about 108 MB |

The size difference is real: an engine that is left out is not linked, and
neither are its dependencies. The OPA-only build contains no Kyverno or
Kubernetes API server code.

The plain `go build` equivalents use build tags:

```bash
go build -tags no_kyverno -o bin/kube-policy-mcp-opa ./cmd/kube-policy-mcp
```

```bash
go build -tags no_opa -o bin/kube-policy-mcp-kyverno ./cmd/kube-policy-mcp
```

## Turning an engine off at run time

```yaml
engines:
  kyverno:
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
internal/engines/builtin/kyverno.go  //go:build !no_kyverno
    imports  internal/engines/kyverno        (blank import)

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
   const EngineName = "gatekeeper"

   func init() {
       engines.Register(engines.Registration{
           Name:         EngineName,
           Title:        "Gatekeeper",
           Description:  "One sentence on what the adapter evaluates.",
           SourceFormat: "What a policy source path must contain.",
           Limitations:  []string{"What it cannot do offline."},
           Module:       "github.com/open-policy-agent/gatekeeper/v3",
           New:          func() policy.Engine { return New() },
       })
   }
   ```

3. Add `internal/engines/builtin/<name>.go`:

   ```go
   //go:build !no_gatekeeper

   package builtin

   import _ "github.com/cosmosdevops/kube-policy-mcp/internal/engines/gatekeeper"
   ```

4. Add a contract test in the adapter package:

   ```go
   func TestEngineContract(t *testing.T) {
       enginetest.Run(t, New(), "path/to/example/policies", manifestYAML)
   }
   ```

That is all. Pack resolution, timeouts, exemptions, required-context checks,
remediation, redaction, the six MCP tools and the CLI work for the new engine
without changes. Use it in the config with `engine: gatekeeper`.

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
  must be compatible across engines even in a single-engine build. This is
  why OPA is pinned to v1.20.2: newer OPA releases and Kyverno 1.20 need
  incompatible versions of `gobwas/glob`. An OPA-only binary does not link
  Kyverno, but it is still built against that pinned OPA.
- **Compile-time plug-ins only.** Adapters are Go packages linked into the
  binary. There is no loading of engines from separate files at run time.
- **The example library and the default tests use both engines.** The example
  packs mix OPA and Kyverno sources, so they only work in the full build.
