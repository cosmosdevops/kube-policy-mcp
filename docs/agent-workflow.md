# Agent workflow

This is the loop an AI coding agent runs with this server:

1. Connect to the MCP server.
2. Discover the policy packs (`list_policy_packs`).
3. Look at the policies that apply to what it is about to write (`list_policies`, `get_policy`).
4. Write a manifest and submit it (`evaluate_manifests`).
5. Read the findings. Each has a message and a fix; `explain_violation` gives more.
6. Correct the manifest and submit it again.
7. Stop when `compliant` is `true`.

No cluster is involved at any point.

## Run it yourself

```bash
make demo
```

This starts the real server over stdio and drives it with a small scripted
client ([examples/mcp/workflow/main.go](../examples/mcp/workflow/main.go)).
The client plays the agent: its "draft" is
[noncompliant/web.yaml](../examples/manifests/noncompliant/web.yaml) and its
"fix" is [compliant/web.yaml](../examples/manifests/compliant/web.yaml).

Output of a real run:

```text
== Step 1: connect ==
connected to kube-policy-mcp dev (protocol 2026-07-28)

== Step 2: discover policy packs (list_policy_packs) ==
- platform-baseline: Enterprise Kubernetes baseline (ownership, resources, pod security, registries, probes)
- production: Baseline plus production-only rules that depend on namespace labels and cluster data
default pack: platform-baseline

== Step 3: inspect the policies that apply to a Deployment (list_policies) ==
- gatekeeper/K8sDisallowHostPath/restrict-hostpath-volumes   high    Restrictions on hostPath volumes
- gatekeeper/K8sRequiredLimits/require-memory-limits         medium  Required memory limits
- opa/kubernetes.approved_registries                         high    Approved container registries
- opa/kubernetes.health_probes                               medium  Required health probes
- opa/kubernetes.required_owner_labels                       high    Required ownership labels
- opa/kubernetes.resource_limits                             high    Required resource requests and limits
- opa/kubernetes.restricted_namespaces                       high    Restricted namespaces
- opa/kubernetes.workload_labels                             low     Recommended workload labels
- vap/disallow-host-namespaces                               high    Prohibited host networking
- vap/disallow-privileged-containers                         high    Restricted container privileges
- vap/require-run-as-non-root                                high    Non-root container execution

== Step 4: evaluate the proposed Deployment (evaluate_manifests) ==
verdict: FAIL (complete: true, compliant: false)
1 resource(s), 11 policies: 15 violation(s), 3 warning(s), 0 unknown, 0 passed, 0 not applicable
- [fail] gatekeeper/K8sDisallowHostPath/restrict-hostpath-volumes: [Implied by expand-workloads] hostPath volume "host-logs" is not allowed. Use a PersistentVolumeClaim, ConfigMap, Secret or emptyDir instead.
    fix: Replace hostPath volumes with a PersistentVolumeClaim, a ConfigMap, a Secret or an emptyDir volume.
- [fail] gatekeeper/K8sRequiredLimits/require-memory-limits: [Implied by expand-workloads] container "web" must set resources.limits.memory
    fix: Set resources.limits.memory on every container.
- [fail] opa/kubernetes.approved_registries: container "web" uses image "nginx:latest", which is not from an approved registry
    fix: Use an image from one of the approved registries listed in the policy data, or ask the platform team to mirror the image.
- [fail] opa/kubernetes.health_probes: container "web" has no readinessProbe
    fix: Add a readinessProbe (and preferably a livenessProbe) to every application container.
- [warning] opa/kubernetes.health_probes: container "web" has no livenessProbe
- [fail] opa/kubernetes.required_owner_labels: Deployment "web" is missing the required label "owner"
    fix: Add non-empty metadata.labels.owner and metadata.labels.team to the resource.
- [fail] opa/kubernetes.required_owner_labels: Deployment "web" is missing the required label "team"
- [fail] opa/kubernetes.resource_limits: container "web" does not set resources.limits.cpu
    fix: Set resources.requests.cpu, resources.requests.memory, resources.limits.cpu and resources.limits.memory on every container.
- [fail] opa/kubernetes.resource_limits: container "web" does not set resources.limits.memory
- [fail] opa/kubernetes.resource_limits: container "web" does not set resources.requests.cpu
- [fail] opa/kubernetes.resource_limits: container "web" does not set resources.requests.memory
- [fail] opa/kubernetes.restricted_namespaces: Deployment "web" targets the restricted namespace "default"
    fix: Set metadata.namespace to a namespace owned by your team.
- [warning] opa/kubernetes.workload_labels: Deployment "web" does not set the recommended label "app.kubernetes.io/name"
    fix: Add the labels app.kubernetes.io/name and app.kubernetes.io/version under metadata.labels.
- [warning] opa/kubernetes.workload_labels: Deployment "web" does not set the recommended label "app.kubernetes.io/version"
- [fail] vap/disallow-host-namespaces: Host networking is not allowed. Remove hostNetwork from the pod spec or set it to false.
    fix: Remove hostNetwork, hostPID and hostIPC from the pod spec, or set them to false.
- [fail] vap/disallow-privileged-containers: Privileged containers are not allowed. Remove securityContext.privileged or set it to false.
    fix: Remove securityContext.privileged (or set it to false) and set securityContext.allowPrivilegeEscalation to false on every container.
- [fail] vap/disallow-privileged-containers: Every container must set securityContext.allowPrivilegeEscalation to false.
- [fail] vap/require-run-as-non-root: Containers must run as non-root. Set runAsNonRoot to true in the pod securityContext or on every container.
    fix: Set securityContext.runAsNonRoot to true in the pod spec, or set securityContext.runAsNonRoot to true on every container.

== Step 5: explain one violation (explain_violation) ==
summary:  Deployment/default/web violates policy opa/kubernetes.approved_registries: container "web" uses image "nginx:latest", which is not from an approved registry
expected: Images must come from an approved registry
actual:   spec.template.spec.containers[0].image = "nginx:latest" (found: true)

== Step 6: evaluate the corrected Deployment (evaluate_manifests) ==
verdict: PASS (complete: true, compliant: true)
2 resource(s), 11 policies: 0 violation(s), 0 warning(s), 0 unknown, 13 passed, 9 not applicable

The corrected manifest complies with the pack. No cluster was contacted.
```

## What the agent should do with each status

| Finding status | Action |
| --- | --- |
| `fail` | Apply the remediation, then evaluate again. |
| `warning` | Optional. Fix it if it is cheap; it does not block. |
| `unknown` | Read `missingContext`. Supply that context and evaluate again. Do not treat it as a pass. |
| `error` | The policy or engine failed. Report it to a human; do not treat it as a pass. |
| `exempted` | Nothing to do. An approved exception covers the resource. |

## Supplying context

Some policies depend on where the manifest will be deployed. With the
`production` pack and no context, three checks cannot be decided:

```bash
kube-policy-mcp evaluate --config examples/kube-policy-mcp.yaml --policy-pack production --file examples/manifests/production/checkout.yaml
```

```text
Verdict:     UNKNOWN (complete: false, compliant: false)
Results:     0 violation(s), 0 warning(s), 3 unknown, 0 error(s), 0 exempted, 11 passed, 0 not applicable

  Deployment/checkout/checkout
    UNKNOWN        gatekeeper/K8sDisallowedTags/disallow-latest-tag-in-production
      cannot determine compliance: the constraint matches on the labels of namespace "checkout", which were not supplied in the context
      missing context: namespace.labels
    UNKNOWN        opa/production.min_replicas
      cannot determine compliance: the policy needs context that was not supplied: namespace.labels
      missing context: namespace.labels
    UNKNOWN        vap/require-registered-team
      cannot determine compliance: binding require-registered-team passes ConfigMap "registered-teams" in namespace platform-system to the policy as its parameter, and it was not found. Supply it in context.resources or put it in the policy source
      missing context: resources
```

Over MCP, the agent adds the context to the same call:

```json
{
  "name": "evaluate_manifests",
  "arguments": {
    "files": ["production/checkout.yaml"],
    "policyPack": "production",
    "context": {
      "namespace": { "name": "checkout", "labels": { "environment": "production" } },
      "resources": [
        {
          "apiVersion": "v1",
          "kind": "ConfigMap",
          "metadata": { "name": "registered-teams", "namespace": "platform-system" },
          "data": { "checkout": "true" }
        }
      ]
    }
  }
}
```

With that context all 14 policies are decided and the manifest passes. The
agent should tell the user which context values it assumed, because the
server cannot verify them.
