# METADATA
# title: Recommended workload labels
# description: Workloads should carry the standard app.kubernetes.io/name and app.kubernetes.io/version labels so that tooling can identify them.
# related_resources:
#   - ref: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
# custom:
#   severity: low
#   category: metadata
#   version: 1.0.0
#   kinds: [Deployment, StatefulSet, DaemonSet, Job, CronJob]
#   remediation: Add the labels app.kubernetes.io/name and app.kubernetes.io/version under metadata.labels.
package kubernetes.workload_labels

recommended := ["app.kubernetes.io/name", "app.kubernetes.io/version"]

# METADATA
# title: Standard workload labels should be present
warn contains result if {
	some label in recommended
	object.get(input.metadata, ["labels", label], "") == ""
	result := {
		"id": label,
		"msg": sprintf("%s %q does not set the recommended label %q", [input.kind, input.metadata.name, label]),
		"field": "metadata.labels",
	}
}
