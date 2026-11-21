# Checking manifests in CI

These files check Kubernetes manifests in a pipeline with two MCP servers:

1. [ojs-mcp](https://github.com/cosmosdevops/ojs-mcp) checks each manifest
   against the Kubernetes and OpenShift schemas.
2. kube-policy-mcp checks it against your policies.

A manifest that fails the schema check is not sent to the policy check.

[check-manifests.yml](check-manifests.yml) is a GitHub Actions workflow that
runs this on the examples in this repository. It also checks that a schema
error, a policy violation and missing context each fail the build.

The workflow is an example and is switched off: it is kept here, outside
`.github/workflows`, so GitHub does not run it. Copy it there to turn it on.

## Run it on your machine

From the repository root:

```bash
make check-manifests
```

This builds kube-policy-mcp, installs ojs-mcp into `bin/`, and runs every
step of the workflow. It needs Go, Python 3 and network access, because
ojs-mcp fetches the schemas.

## Files

| File | Purpose |
| --- | --- |
| `check-manifests.yml` | The example GitHub Actions workflow. |
| `check_manifests.py` | Runs both checks on files or directories and prints the problems. |
| `mcp_call.py` | Calls one tool on an MCP server over stdio. Used by the script above, and usable on its own. |
| `local-run.sh` | The workflow's steps as a script. `make check-manifests` runs it. |
| `invalid-schema.yaml` | A manifest with schema errors, for the test. |
| `production-context.json` | Context for the `production` pack, for the test. |

Both scripts need only Python 3. There is nothing to install with `pip`.

## Check your own manifests

With `ojs-mcp` and `kube-policy-mcp` on your `PATH`:

```bash
python3 examples/ci/check_manifests.py --config examples/kube-policy-mcp.yaml examples/manifests/compliant
```

```text
PASS  examples/manifests/compliant/web.yaml
      schema: valid (OpenShift 5.0)
      policy: compliant (11 policies: 0 violations, 0 warnings, 0 undecided)

1 of 1 file(s) passed
```

It exits with `0` when every file passes, `1` when a file fails either check
or a policy could not be decided, and `3` when a server cannot be used.

Problems are printed as GitHub Actions annotations, so they appear on the
pull request next to the file:

```text
::error file=k8s/web.yaml,title=Schema::Deployment web: /spec/replicas: got string, want null or integer
```

Options:

| Option | Meaning |
| --- | --- |
| `--config` | The kube-policy-mcp config file. Required. |
| `--policy-pack` | The pack to check against. Default: the config's default pack. |
| `--context-file` | A JSON file with the evaluation context, such as namespace labels. |
| `--openshift-version` | The OpenShift version for the schemas. Default: the newest. |

## Use it in your own repository

Copy `check_manifests.py` and `mcp_call.py`, and put `check-manifests.yml`
in `.github/workflows/`. In the workflow, install a release of
kube-policy-mcp instead of building it:

```yaml
- name: Install the MCP servers
  run: |
    go install github.com/cosmosdevops/ojs-mcp@v0.2.1
    go install github.com/cosmosdevops/kube-policy-mcp/cmd/kube-policy-mcp@v0.1.0

- name: Check the manifests
  run: python3 ci/check_manifests.py --config kube-policy-mcp.yaml k8s/
```

The steps in the workflow that expect a failure are tests of the tools
themselves. You do not need them.

## Why MCP in a pipeline

An agent is the usual caller of these servers. In CI there is no agent, so
`mcp_call.py` speaks the protocol directly: it starts the server, sends
`initialize`, calls one tool and reads the answer. That way the pipeline runs
the same tools, with the same results, as the agent that wrote the manifest.

kube-policy-mcp also has a plain command, `kube-policy-mcp evaluate`, which
does the policy check without MCP. ojs-mcp has no such command, so the script
uses MCP for both.
