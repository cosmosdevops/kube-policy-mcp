# Helper functions shared by the baseline Rego policies.
# This package has no deny or warn rules, so it is not listed as a policy.
package lib.kubernetes

controller_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job"}

# pod_spec_path returns the field path of the pod spec inside a workload.
pod_spec_path(obj) := "spec" if obj.kind == "Pod"

pod_spec_path(obj) := "spec.template.spec" if obj.kind in controller_kinds

pod_spec_path(obj) := "spec.jobTemplate.spec.template.spec" if obj.kind == "CronJob"

pod_spec(obj) := obj.spec if obj.kind == "Pod"

pod_spec(obj) := obj.spec.template.spec if obj.kind in controller_kinds

pod_spec(obj) := obj.spec.jobTemplate.spec.template.spec if obj.kind == "CronJob"

# containers returns every container of a workload with its field path.
containers(obj) := [entry |
	some type in ["containers", "initContainers"]
	some i, container in object.get(pod_spec(obj), type, [])
	entry := {
		"container": container,
		"type": type,
		"path": sprintf("%s.%s[%d]", [pod_spec_path(obj), type, i]),
	}
]
