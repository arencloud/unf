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
require 'encryption_key_epoch_floor_defers_until_draining_predecessor_retires' \
    "${root}/bins/unf-agent/src/main.rs"
require 'replacement_pod_authority_retry_is_bounded_and_fail_closed' \
    "${root}/bins/unf-agent/src/main.rs"

for bounded_wait in wait_generation_after wait_epoch_change; do
    wait_body=$(sed -n "/^${bounded_wait}()/,/^}/p" "${gate}")
    rg -q 'generation_snapshot' <<<"${wait_body}" || {
        echo "${bounded_wait} must inspect one direct generation snapshot per retry" >&2
        exit 1
    }
    if rg -q 'wait_generation true' <<<"${wait_body}"; then
        echo "${bounded_wait} must not nest the independent convergence timeout" >&2
        exit 1
    fi
done

echo "Phase 9.8 Kind qualification gate contract verified"
