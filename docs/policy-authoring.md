# Writing policies

Policies stay in their native format. This page lists the few conventions the
server reads so that agents get useful metadata, applicability and fixes.

Nothing here is required for a policy to run. But the server does not invent
descriptions or fixes: what you do not declare is left empty.

## Rego

A policy is a package with at least one of these rules:

| Rule | Result |
| --- | --- |
| `deny`, `violation` | `fail` |
| `warn` | `warning` |
| `unknown` | `unknown` (compliance cannot be decided) |
| `applies` (boolean, optional) | when not true, the policy is `not_applicable` |

The Kubernetes resource is `input`, as with Conftest.

```rego
# METADATA
# title: Required ownership labels
# description: Workloads must carry the owner and team labels.
# related_resources:
#   - ref: https://wiki.example.com/platform/labels
# custom:
#   severity: high
#   category: ownership
#   version: 1.0.0
#   kinds: [Pod, Deployment, StatefulSet]
#   remediation: Add metadata.labels.owner and metadata.labels.team.
package kubernetes.required_owner_labels

# METADATA
# title: Each ownership label must be present
deny contains result if {
	some label in ["owner", "team"]
	object.get(input.metadata, ["labels", label], "") == ""
	result := {
		"id": label,
		"msg": sprintf("%s %q is missing the label %q", [input.kind, input.metadata.name, label]),
		"field": sprintf("metadata.labels.%s", [label]),
	}
}
```

### Package metadata

| Annotation | Used for |
| --- | --- |
| `title`, `description` | Shown in listings and explanations. |
| `related_resources`, `custom.docs` | Documentation links. |
| `custom.severity` | Free text, for example `low`, `medium`, `high`, `critical`. |
| `custom.category`, `custom.version` | Shown in listings. |
| `custom.kinds` | Kinds the policy applies to. Other kinds are `not_applicable`. **Without it the policy applies to every kind.** |
| `custom.remediation` | The fix shown with each violation. |
| `custom.requiredContext` | Context the policy needs. If any is missing the result is `unknown`. |

`requiredContext` keys: `namespace`, `namespace.labels`, `operation`, `user`,
`user.groups`, `kubernetesVersion`, `variables.<name>`, `data.<name>`.

A `title` on a rule (rule-scope `# METADATA`) is used as the expected
behaviour in explanations.

### Rule results

A result can be a string, or an object with these optional keys:

| Key | Meaning |
| --- | --- |
| `msg` or `message` | The message. |
| `field` | Path of the offending field, for example `spec.template.spec.containers[0].image`. Lets `explain_violation` show the observed value. |
| `id` | Added to the rule id, for example `deny/owner`. |
| `remediation` | A fix for this specific result. Overrides the package one. |
| `severity` | Overrides the package severity. |
| `missingContext` | For `unknown` results: what is missing. |

Any other key is kept under `details`.

### Context

```rego
data.kubepolicy.context.operation          # "CREATE", "UPDATE" or "DELETE"
data.kubepolicy.context.kubernetesVersion
data.kubepolicy.context.user.username
data.kubepolicy.context.user.groups
data.kubepolicy.context.variables.environment
data.kubepolicy.context.namespace          # name of the target namespace
data.kubepolicy.namespaces[name].labels    # metadata of known namespaces
data.kubepolicy.resources                  # all submitted and context resources
data.kubepolicy.data                       # free-form caller data
```

`data.kubepolicy` is reserved. Your own data files (`data.yaml`, `data.json`)
are loaded at the path given by their directory: `teams/data.yaml` becomes
`data.teams`.

Caller data lives under `data.kubepolicy.data` on purpose. A caller cannot
overwrite your policy data, such as an approved-registry list.

A policy that only applies under some context should say so, so that missing
context becomes `unknown` rather than a quiet "does not apply":

```rego
# METADATA
# custom:
#   kinds: [Deployment]
#   requiredContext: [namespace.labels]
package production.min_replicas

applies if data.kubepolicy.namespaces[input.metadata.namespace].labels.environment == "production"

deny contains "need at least 2 replicas" if object.get(input.spec, "replicas", 1) < 2
```

### Not allowed

`http.send`, `net.lookup_ip_addr` and `opa.runtime` are removed. A policy
using them does not compile and evaluates to `error`. Because a source is one
compile unit, that also breaks the other policies in the same directory.

## Kyverno

Supported: `ValidatingPolicy`, `NamespacedValidatingPolicy` and
`PolicyException` in the `policies.kyverno.io` group.

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-host-namespaces
  annotations:
    policies.kyverno.io/title: Prohibited host networking
    policies.kyverno.io/category: Pod Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: Pods must not share the host network, PID or IPC namespaces.
    kubepolicy.dev/remediation: Remove hostNetwork, hostPID and hostIPC from the pod spec.
spec:
  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: "!object.spec.?hostNetwork.orValue(false)"
      message: Host networking is not allowed.
```

### Annotations

| Annotation | Used for |
| --- | --- |
| `policies.kyverno.io/title`, `/description`, `/category`, `/severity` | Standard Kyverno metadata. |
| `kubepolicy.dev/remediation` | The fix shown with each violation. |
| `kubepolicy.dev/docs` | Comma-separated documentation links. |
| `kubepolicy.dev/version` | Policy version. |
| `kubepolicy.dev/required-context` | Comma-separated context keys, same keys as for Rego. |

Some required context is detected for you: a `namespaceSelector` needs
`namespace.labels`, `namespaceObject` needs `namespace`, and
`request.userInfo` needs `user`.

### Things to know

- **Enforcement.** `Deny` gives `fail`. `Warn` or `Audit` alone give `warning`.
- **Autogen.** A policy that matches `pods` is also applied to Deployments,
  StatefulSets, DaemonSets, Jobs, CronJobs and ReplicaSets, as in a cluster.
- **One finding per policy.** Kyverno stops at the first failing validation.
  Split unrelated checks into separate policies if you want them all listed.
- **Field and per-result fix.** Add `auditAnnotations` with the keys `field`
  or `remediation` and they are copied into the finding. Careful with
  autogen: a literal such as `'spec.hostNetwork'` is not rewritten for a
  Deployment, where the real path is `spec.template.spec.hostNetwork`.
- **Lookups.** `resource.Get` and `resource.List` only see the submitted
  manifests and `context.resources`. If the object is not there, the result
  is `unknown`.
- **Not run offline.** Policies using the `http` library, `image.GetMetadata`,
  `resource.Post` or `resource.ToGVR` evaluate to `unknown`.
- **Exceptions.** Put `PolicyException` files anywhere in a Kyverno source.
  They apply to every policy in the resolved pack that they reference.
- **Legacy policies.** `kyverno.io/v1` `ClusterPolicy` and `Policy` were
  removed in Kyverno 1.20. They are listed as unsupported and evaluate to
  `unknown`. Convert them to `ValidatingPolicy`.

## Checking your policies

```bash
kube-policy-mcp policies --policy-pack my-pack
```

A policy that failed to load is listed with `[NOT EVALUABLE: ...]` and the
reason. Keep a compliant and a non-compliant manifest next to each policy and
evaluate both in CI:

```bash
kube-policy-mcp evaluate --dir ./fixtures/compliant --policy-pack my-pack
```
