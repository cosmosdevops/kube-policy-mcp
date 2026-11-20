# METADATA
# title: Approved container registries
# description: Container images must be pulled from a registry on the approved list. The list is policy data (data.approved_registries) maintained with the policies.
# custom:
#   severity: high
#   category: supply-chain
#   version: 1.0.0
#   kinds: [Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob]
#   remediation: Use an image from one of the approved registries listed in the policy data, or ask the platform team to mirror the image.
package kubernetes.approved_registries

import data.lib.kubernetes

approved(image) if {
	some prefix in data.approved_registries
	startswith(image, prefix)
}

# METADATA
# title: Images must come from an approved registry
deny contains result if {
	some entry in kubernetes.containers(input)
	image := object.get(entry.container, "image", "")
	not approved(image)
	result := {
		"msg": sprintf("container %q uses image %q, which is not from an approved registry", [entry.container.name, image]),
		"field": sprintf("%s.image", [entry.path]),
		"approvedRegistries": data.approved_registries,
	}
}
