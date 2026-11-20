# METADATA
# title: Required health probes
# description: Long-running workloads must define a readiness probe so that traffic is only sent to ready pods. A liveness probe is recommended.
# custom:
#   severity: medium
#   category: reliability
#   version: 1.0.0
#   kinds: [Deployment, StatefulSet, DaemonSet]
#   remediation: Add a readinessProbe (and preferably a livenessProbe) to every application container.
package kubernetes.health_probes

import data.lib.kubernetes

app_containers contains entry if {
	some entry in kubernetes.containers(input)
	entry.type == "containers"
}

# METADATA
# title: Containers must define a readiness probe
deny contains result if {
	some entry in app_containers
	not entry.container.readinessProbe
	result := {
		"id": "readiness",
		"msg": sprintf("container %q has no readinessProbe", [entry.container.name]),
		"field": sprintf("%s.readinessProbe", [entry.path]),
	}
}

# METADATA
# title: Containers should define a liveness probe
warn contains result if {
	some entry in app_containers
	not entry.container.livenessProbe
	result := {
		"id": "liveness",
		"msg": sprintf("container %q has no livenessProbe", [entry.container.name]),
		"field": sprintf("%s.livenessProbe", [entry.path]),
		"remediation": "Add a livenessProbe so that a hung container is restarted.",
	}
}
