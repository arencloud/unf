#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
gate=${root}/hack/verify-openshift-encryption-phase9.sh
overlay=${root}/deploy/openshift-primary-cni/encryption-phase9
release=${overlay}/release.json
rendered=$(mktemp)
trap 'rm -f "${rendered}"' EXIT

bash -n "${gate}"
oc kustomize "${overlay}" >"${rendered}"
jq -e '
  .schemaVersion == 1 and .phase == "9.9"
  and .kindQualification.milestone == "9.8"
  and .kindQualification.runtimeRevision == .sourceRevision
  and .kindQualification.result == "passed"
  and .kindQualification.kubeProxyPresent == false
  and .contracts.encryptionMapAbiVersion == 2
  and all(.images[]; test("@sha256:[0-9a-f]{64}$"))
' "${release}" >/dev/null

require() {
    rg -q "$1" "$2" || {
        echo "missing Phase 9.9 gate invariant '$1' in $2" >&2
        exit 1
    }
}

require 'UNF_OPENSHIFT_ENCRYPTION_ACKNOWLEDGE_DISPOSABLE' "${gate}"
require 'UNF_OPENSHIFT_ENCRYPTION_ACKNOWLEDGE_MIGRATION' "${gate}"
require 'explicitly-acknowledged-required-migration' "${gate}"
require 'selective-native-exception' "${gate}"
require 'ciphertext-and-fail-closed' "${gate}"
require 'tcpdump.*br-ex' "${gate}"
require 'requiredPlaintextFrames' "${gate}"
require 'wait_epoch_change' "${gate}"
require '/v1/encryption/status' "${gate}"
require 'lossAffected == false' "${gate}"
require 'exact-cleanup' "${gate}"
require 'baseline_unhealthy' "${gate}"
require 'final_unhealthy' "${gate}"
require 'simultaneous replacement of every encrypted endpoint' "${gate}"
require 'must_establish_initial_generation' "${root}/bins/unf-agent/src/main.rs"
require 'oc image info .*--filter-by-os=linux/amd64 -o json' \
    "${root}/hack/deploy-openshift-service-fabric.sh"
require 'reconcile_bootstrap_epoch_floor' "${root}/bins/unf-agent/src/main.rs"
require 'node_block_startup_authority_retry' "${root}/bins/unf-agent/src/main.rs"
require '/v1/state/encryption-activation-testimony' "${root}/bins/unf-agent/src/main.rs"
require 'encryption_activation_testimony' "${root}/bins/unf-controller/src/main.rs"
require 'assert_phase9_agent_staging' "${root}/hack/deploy-openshift-service-fabric.sh"
require 'Monotonic Fleet Key Epoch Floor' "${root}/docs/adr/0215-monotonic-fleet-key-epoch-floor.md"
require 'Demand-Driven Reciprocal Activation Testimony' "${root}/docs/adr/0219-demand-driven-reciprocal-activation-testimony.md"
require 'Retirement-Before-Catch-Up' "${root}/docs/adr/0225-retirement-before-catch-up.md"
require 'UNF_ENCRYPTION_BASELINE' "${overlay}/controller-native-patch.yaml"
require 'value: native' "${overlay}/controller-native-patch.yaml"
require 'UNF_ENCRYPTION_KEY_LIFETIME_SECONDS' "${overlay}/agent-rotation-patch.yaml"

controller_image=$(jq -er .images.controller "${release}")
agent_image=$(jq -er .images.agent "${release}")
grep -Fq "image: ${controller_image}" "${rendered}"
[[ $(grep -Fc "image: ${agent_image}" "${rendered}") == 2 ]]
grep -Fq 'value: native' "${rendered}"

echo "Phase 9.9 OpenShift encryption qualification gate contract verified"
