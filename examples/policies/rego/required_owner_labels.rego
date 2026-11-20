# METADATA
# title: Required ownership labels
# description: Workloads and services must carry the owner and team labels so that every resource can be traced to an accountable team.
# custom:
#   severity: high
#   category: ownership
#   version: 1.0.0
#   kinds: [Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob, Service]
#   remediation: Add non-empty metadata.labels.owner and metadata.labels.team to the resource.
package kubernetes.required_owner_labels

required_labels := ["owner", "team"]

# METADATA
# title: Each ownership label must be present and non-empty
deny contains result if {
	some label in required_labels
	object.get(input.metadata, ["labels", label], "") == ""
	result := {
		"id": label,
		"msg": sprintf("%s %q is missing the required label %q", [input.kind, input.metadata.name, label]),
		"field": sprintf("metadata.labels.%s", [label]),
	}
}
