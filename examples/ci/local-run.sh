#!/usr/bin/env bash
# Runs the steps of check-manifests.yml on this machine. It needs ojs-mcp
# and kube-policy-mcp on the PATH. The easy way is from the repository root:
#
#   make check-manifests
set -euo pipefail

CHECK="python3 examples/ci/check_manifests.py --config examples/kube-policy-mcp.yaml"
step() { printf '\n##### %s\n' "$1"; }

step "Manifests pass both checks"
$CHECK examples/manifests/compliant

step "A manifest that needs context passes when it is given"
$CHECK --policy-pack production --context-file examples/ci/production-context.json examples/manifests/production/checkout.yaml

step "A schema error is caught"
if out=$($CHECK examples/ci/invalid-schema.yaml 2>&1); then
  echo "a manifest with schema errors passed"; echo "$out"; exit 1
fi
echo "$out" | sed 's/^::/  /'
echo "$out" | grep -q 'title=Schema'
echo "$out" | grep -q 'policy: skipped'

step "A policy violation is caught"
if out=$($CHECK examples/manifests/noncompliant 2>&1); then
  echo "a manifest that breaks policies passed"; echo "$out"; exit 1
fi
echo "$out" | sed 's/^::/  /' | tail -4
echo "$out" | grep -q 'schema: valid'
echo "$out" | grep -q 'policy: not compliant'

step "Missing context is not a pass"
if out=$($CHECK --policy-pack production examples/manifests/production/checkout.yaml 2>&1); then
  echo "a manifest passed although some checks could not be decided"; echo "$out"; exit 1
fi
echo "$out" | sed 's/^::/  /'
echo "$out" | grep -q 'undecided'

printf '\nAll steps behaved as expected.\n'
