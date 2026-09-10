#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
gate=${root}/hack/verify-kind-encryption-phase9.sh
overlay=${root}/deploy/kind-encryption-phase9

bash -n "${gate}"
kubectl kustomize "${overlay}" >/dev/null

require() {
    rg -q "$1" "$2" || {
        echo "missing Phase 9.8 gate invariant '$1' in $2" >&2
        exit 1
    }
}

require 'UNF_ENCRYPTION_BASELINE' "${overlay}/controller-required-patch.yaml"
require 'value: required' "${overlay}/controller-required-patch.yaml"
require 'UNF_ENCRYPTION_KEY_LIFETIME_SECONDS' "${overlay}/agent-rotation-patch.yaml"
require 'default-required' "${gate}"
require 'selective-native-exception' "${gate}"
require 'ciphertext-and-fail-closed' "${gate}"
require 'wait_epoch_change' "${gate}"
require '/v1/encryption/status' "${gate}"
require 'verify-kind-egress-lifecycle.sh' "${gate}"
require 'verify-encryption-performance.sh' "${gate}"
require 'rollback-kind-primary-cni.sh' "${gate}"
require 'requiredPlaintextFrames' "${gate}"
require 'imageID' "${gate}"

echo "Phase 9.8 Kind qualification gate contract verified"
