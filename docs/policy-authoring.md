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

## ValidatingAdmissionPolicy

Supported: `ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding`
from `admissionregistration.k8s.io/v1`. Use `engine: vap` in the config.

A policy does nothing until a binding puts it into effect, in a cluster and
here. Keep each policy and its bindings in the same source directory.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: disallow-host-namespaces
  annotations:
    kubepolicy.cosmos.dev/title: Prohibited host networking
    kubepolicy.cosmos.dev/category: Pod Security
    kubepolicy.cosmos.dev/severity: high
    kubepolicy.cosmos.dev/description: Pods must not share the host network, PID or IPC namespaces.
    kubepolicy.cosmos.dev/remediation: Remove hostNetwork, hostPID and hostIPC from the pod spec.
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments", "statefulsets", "daemonsets"]
  variables:
    - name: podSpec
      expression: "object.kind == 'Pod' ? object.spec : object.spec.template.spec"
  validations:
    - expression: "!variables.podSpec.?hostNetwork.orValue(false)"
      message: Host networking is not allowed.
    - expression: "!variables.podSpec.?hostPID.orValue(false)"
      message: Sharing the host PID namespace is not allowed.
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: disallow-host-namespaces
spec:
  policyName: disallow-host-namespaces
  validationActions: [Deny]
```

### Annotations

Kubernetes defines no metadata annotations for admission policies, so these
are this project's own. All are optional.

| Annotation | Used for |
| --- | --- |
| `kubepolicy.cosmos.dev/title`, `/description`, `/category`, `/severity` | Shown in listings and explanations. |
| `kubepolicy.cosmos.dev/remediation` | The fix shown with each violation. |
| `kubepolicy.cosmos.dev/docs` | Comma-separated documentation links. |
| `kubepolicy.cosmos.dev/version` | Policy version. |
| `kubepolicy.cosmos.dev/required-context` | Comma-separated context keys, same keys as for Rego. |

Some required context is detected for you: a `namespaceSelector` (on the
policy or a binding) and `namespaceObject` need `namespace.labels`, and
`request.userInfo` needs `user`.

### Things to know

- **Bindings.** A policy with no binding in its source is reported as
  `unknown`, because it enforces nothing and that is probably a mistake.
  A policy can have several bindings; it is evaluated through each one that
  selects the resource.
- **Enforcement.** It comes from the binding's `validationActions`. `Deny`
  gives `fail`. `Warn` or `Audit` alone give `warning`.
- **Every failing validation is reported**, each with the rule id
  `validations[<index>]`.
- **No autogen.** A policy that matches only `pods` does not apply to a
  Deployment. Match the pod controllers in `resourceRules` and find the pod
  spec with a variable, as in the example above.
- **Parameters.** With `paramKind` on the policy and `paramRef` on the
  binding, the parameter object is looked up in the submitted manifests, in
  `context.resources`, and in the policy source directory. So you can keep
  parameter objects (a ConfigMap, or your own custom resource) next to the
  policy. If the object is not found the result is `unknown`, whatever
  `parameterNotFoundAction` says: offline, "not found" only means "not
  supplied".
- **Field and per-result fix.** Add `auditAnnotations` and they are copied
  into the findings. Use the key `field.<index>` or `remediation.<index>`
  for one validation. The plain keys `field` and `remediation` are used
  when exactly one validation failed.

  ```yaml
  auditAnnotations:
    - key: field.0
      valueExpression: "object.kind == 'Pod' ? 'spec.hostNetwork' : 'spec.template.spec.hostNetwork'"
  ```

- **Errors are never a pass.** A CEL error at evaluation gives `error`, also
  with `failurePolicy: Ignore`. In a cluster `Ignore` would let the request
  through without having checked it.
- **No type checking.** Expressions are compiled without resource schemas.
  A wrong field name is an `error` when the policy is evaluated, not when it
  is loaded. Use optional access (`object.spec.?field.orValue(...)`) for
  fields that may be absent.
- **Not run offline.** Policies that use the `authorizer` variable evaluate
  to `unknown`. `MutatingAdmissionPolicy` is listed as unsupported.

## Gatekeeper

Supported: `ConstraintTemplate` (Rego or Kubernetes CEL code), constraints,
`ExpansionTemplate` and `Config`. Use `engine: gatekeeper` in the config.

A `ConstraintTemplate` holds the logic and enforces nothing by itself. A
constraint puts it into effect: where it applies, with which parameters and
with which action. So **each constraint is one policy**, with the id
`gatekeeper/<constraint kind>/<constraint name>`. Keep a constraint and its
template in the same source directory.

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlimits
  annotations:
    metadata.gatekeeper.sh/title: Required resource limits
    description: Every container must set a limit for each of the listed resources.
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLimits
      validation:
        openAPIV3Schema:
          type: object
          properties:
            resources:
              type: array
              items: {type: string}
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlimits

        violation[{"msg": msg, "details": {"container": container.name}}] {
          container := input.review.object.spec.containers[_]
          resource := input.parameters.resources[_]
          not container.resources.limits[resource]
          msg := sprintf("container %q must set resources.limits.%s", [container.name, resource])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLimits
metadata:
  name: require-memory-limits
  annotations:
    kubepolicy.cosmos.dev/severity: medium
    kubepolicy.cosmos.dev/remediation: Set resources.limits.memory on every container.
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    resources: ["memory"]
```

### Annotations

Annotations are read from the constraint first, then from its template. So a
template can carry the general text and each constraint can override it.

| Annotation | Used for |
| --- | --- |
| `kubepolicy.cosmos.dev/title`, or `metadata.gatekeeper.sh/title` | Title. |
| `kubepolicy.cosmos.dev/description`, or `description` | Description. |
| `kubepolicy.cosmos.dev/severity`, `/category` | Shown in listings. |
| `kubepolicy.cosmos.dev/remediation` | The fix shown with each violation. |
| `kubepolicy.cosmos.dev/docs` | Comma-separated documentation links. |
| `kubepolicy.cosmos.dev/version`, or `metadata.gatekeeper.sh/version` | Version. |
| `kubepolicy.cosmos.dev/required-context` | Comma-separated context keys, same keys as for Rego. |

The `metadata.gatekeeper.sh/*` and `description` annotations are the ones the
Gatekeeper policy library uses, so its templates work unchanged.

### Things to know

- **Enforcement.** `enforcementAction: deny` (the default) gives `fail`.
  `warn` and `dryrun` give `warning`. With `scoped`, the actions for the
  admission enforcement point (`validation.gatekeeper.sh`) are used; a
  constraint with no action there is `not_applicable`.
- **Every violation is reported.**
- **Matching.** `spec.match` is evaluated by Gatekeeper's own code: `kinds`,
  `namespaces`, `excludedNamespaces`, `labelSelector`, `namespaceSelector`,
  `scope`, `name` and `source`. A `namespaceSelector` needs the namespace
  labels in the context; without them the result is `unknown`.
- **Parameters.** `spec.parameters` is checked against the template's
  schema when the source is loaded. A constraint that does not fit is listed
  with the error and evaluates to `error`.
- **Pod controllers.** A constraint that matches `Pod` does not select a
  Deployment. Either match the controller kinds and find the pod spec in the
  template code, or add an `ExpansionTemplate` to the source. With one,
  Gatekeeper also checks the Pod a workload would create, and prefixes those
  violations with `[Implied by <expansion template>]`.
- **Field and per-result fix.** If a violation's `details` holds a `field`
  or `remediation` string, it is copied into the finding. Other details are
  kept under `details`.
- **Referential constraints.** Templates can read other objects through
  `data.inventory`. The inventory holds the submitted manifests, the known
  namespaces and `context.resources`. A template that reads it requires
  `context.resources`; without it the result is `unknown`, because the
  server cannot know what else is in the cluster.
- **Exclusions.** A `Config` resource in the source can exclude namespaces
  (`spec.match` with process `webhook` or `*`). Resources there are
  `exempted` for every constraint of that source.
- **Unused templates.** A template that no constraint in the source uses is
  only reported as a load warning.
- **Not run offline.** `http.send`, `net.lookup_ip_addr` and `opa.runtime`
  are removed. Templates that call `external_data` evaluate to `unknown`.
- **Mutators.** `Assign`, `AssignMetadata`, `ModifySet` and `AssignImage`
  are only applied to resources generated by an `ExpansionTemplate`.

## Checking your policies

```bash
kube-policy-mcp policies --policy-pack my-pack
```

A policy that failed to load is listed with `[NOT EVALUABLE: ...]` and the
reason. Load warnings, such as an unused template or an ignored file, are
listed under `Notes`, here and in every evaluation result. Keep a compliant and a non-compliant manifest next to each policy and
evaluate both in CI:

```bash
kube-policy-mcp evaluate --dir ./fixtures/compliant --policy-pack my-pack
```
