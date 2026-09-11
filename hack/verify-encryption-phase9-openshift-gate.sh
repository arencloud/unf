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
require 'UNF_ENCRYPTION_BASELINE' "${overlay}/controller-native-patch.yaml"
require 'value: native' "${overlay}/controller-native-patch.yaml"
require 'UNF_ENCRYPTION_KEY_LIFETIME_SECONDS' "${overlay}/agent-rotation-patch.yaml"

controller_image=$(jq -er .images.controller "${release}")
agent_image=$(jq -er .images.agent "${release}")
grep -Fq "image: ${controller_image}" "${rendered}"
[[ $(grep -Fc "image: ${agent_image}" "${rendered}") == 2 ]]
grep -Fq 'value: native' "${rendered}"

echo "Phase 9.9 OpenShift encryption qualification gate contract verified"
