# METADATA
# title: Required resource requests and limits
# description: Every container must declare CPU and memory requests and limits so that the scheduler can place it and one workload cannot starve others.
# custom:
#   severity: high
#   category: resources
#   version: 1.0.0
#   kinds: [Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob]
#   remediation: Set resources.requests.cpu, resources.requests.memory, resources.limits.cpu and resources.limits.memory on every container.
package kubernetes.resource_limits

import data.lib.kubernetes

required := [["requests", "cpu"], ["requests", "memory"], ["limits", "cpu"], ["limits", "memory"]]

# METADATA
# title: Each container must set CPU and memory requests and limits
deny contains result if {
	some entry in kubernetes.containers(input)
	some path in required
	object.get(entry.container, array.concat(["resources"], path), "") == ""
	result := {
		"id": concat(".", path),
		"msg": sprintf("container %q does not set resources.%s", [entry.container.name, concat(".", path)]),
		"field": sprintf("%s.resources.%s", [entry.path, concat(".", path)]),
	}
}
