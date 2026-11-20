# METADATA
# title: Production workloads need at least two replicas
# description: Deployments and StatefulSets in a namespace labelled environment=production must run at least two replicas. The policy needs the labels of the target namespace.
# custom:
#   severity: high
#   category: reliability
#   version: 1.0.0
#   kinds: [Deployment, StatefulSet]
#   requiredContext: [namespace.labels]
#   remediation: Set spec.replicas to 2 or more.
package production.min_replicas

namespace := data.kubepolicy.namespaces[input.metadata.namespace]

# The policy only applies in production namespaces.
applies if namespace.labels.environment == "production"

# METADATA
# title: spec.replicas must be at least 2
deny contains result if {
	replicas := object.get(input.spec, "replicas", 1)
	replicas < 2
	result := {
		"msg": sprintf("%s %q runs %d replica(s) in production namespace %q; at least 2 are required", [input.kind, input.metadata.name, replicas, input.metadata.namespace]),
		"field": "spec.replicas",
	}
}
