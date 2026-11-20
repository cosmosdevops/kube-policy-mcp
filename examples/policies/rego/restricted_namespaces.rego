# METADATA
# title: Restricted namespaces
# description: Application resources must not be deployed into the default namespace or into system namespaces.
# custom:
#   severity: high
#   category: multi-tenancy
#   version: 1.0.0
#   kinds: [Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob, Service, ConfigMap, Secret]
#   remediation: Set metadata.namespace to a namespace owned by your team.
package kubernetes.restricted_namespaces

restricted := {"default", "kube-system", "kube-public", "kube-node-lease"}

namespace := object.get(input.metadata, "namespace", "")

# METADATA
# title: Resources must not use a restricted namespace
deny contains result if {
	namespace in restricted
	result := {
		"msg": sprintf("%s %q targets the restricted namespace %q", [input.kind, input.metadata.name, namespace]),
		"field": "metadata.namespace",
	}
}

# Without a namespace the resource lands in whatever namespace the deployer's
# kubeconfig points at, so compliance cannot be decided from the manifest.
unknown contains result if {
	namespace == ""
	result := {
		"msg": sprintf("%s %q has no metadata.namespace and no target namespace was given, so the namespace it will be deployed to is not known", [input.kind, input.metadata.name]),
		"missingContext": ["namespace"],
	}
}
