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
require 'new_unhealthy=' "${gate}"
require 'newlyUnhealthyOperators' "${gate}"
require 'timeout 20.*exec' "${gate}"
require 'http://127.0.0.1:9962' "${gate}"
require 'request-timeout=' "${gate}"
require 'simultaneous replacement of every encrypted endpoint' "${gate}"
require 'kind: DaemonSet' "${gate}"
require 'unf-encryption-host-probe' "${gate}"
require 'chroot /host' "${gate}"
require 'baseline_changed' "${gate}"
require 'must_establish_initial_generation' "${root}/bins/unf-agent/src/main.rs"
require 'oc image info .*--filter-by-os=linux/amd64 -o json' \
    "${root}/hack/deploy-openshift-service-fabric.sh"
require 'reconcile_bootstrap_epoch_floor' "${root}/bins/unf-agent/src/main.rs"
require 'node_block_startup_authority_retry' "${root}/bins/unf-agent/src/main.rs"
require 'native_only_generation_closes_without_encrypted_path_exchange' \
    "${root}/bins/unf-agent/src/main.rs"
require '/v1/state/encryption-activation-testimony' "${root}/bins/unf-agent/src/main.rs"
require 'encryption_activation_testimony' "${root}/bins/unf-controller/src/main.rs"
require 'assert_phase9_agent_staging' "${root}/hack/deploy-openshift-service-fabric.sh"
require 'Monotonic Fleet Key Epoch Floor' "${root}/docs/adr/0215-monotonic-fleet-key-epoch-floor.md"
require 'Demand-Driven Reciprocal Activation Testimony' "${root}/docs/adr/0219-demand-driven-reciprocal-activation-testimony.md"
require 'Retirement-Before-Catch-Up' "${root}/docs/adr/0225-retirement-before-catch-up.md"
require 'Proof-Carrying Zero-Transport Closure' \
    "${root}/docs/adr/0227-proof-carrying-zero-transport-closure.md"
require 'Activation-Before-Recovery-Successor' \
    "${root}/docs/adr/0228-activation-before-recovery-successor.md"
require 'Immutable Activation-Ordered Kind Requalification' \
    "${root}/docs/adr/0229-immutable-activation-ordered-kind-requalification.md"
require 'Non-Perturbing Fleet Witness' \
    "${root}/docs/adr/0230-non-perturbing-fleet-witness.md"
require 'Expired Authority Recovery' \
    "${root}/docs/adr/0231-expired-authority-recovery.md"
require 'Crash-Residue Cleanup Closure' \
    "${root}/docs/adr/0232-crash-residue-cleanup-closure.md"
require 'Immutable Expiry-Recovery Kind Requalification' \
    "${root}/docs/adr/0233-immutable-expiry-recovery-kind-requalification.md"
require 'Causal Readiness Join' \
    "${root}/docs/adr/0234-causal-readiness-join.md"
require 'Monotonic Platform Health Delta' \
    "${root}/docs/adr/0235-monotonic-platform-health-delta.md"
require 'Conflict-Acknowledged Activation Supersession' \
    "${root}/docs/adr/0236-conflict-acknowledged-activation-supersession.md"
require 'Immutable Activation-Supersession Kind Requalification' \
    "${root}/docs/adr/0237-immutable-activation-supersession-kind-requalification.md"
require 'Bounded Node-Local Control Witness' \
    "${root}/docs/adr/0238-bounded-node-local-control-witness.md"
require 'Whole-Gate API Deadline' \
    "${root}/docs/adr/0239-whole-gate-api-deadline.md"
require 'Tombstone-Aware Generation Handoff' \
    "${root}/docs/adr/0240-tombstone-aware-generation-handoff.md"
require 'Immutable Tombstone-Handoff Kind Requalification' \
    "${root}/docs/adr/0241-immutable-tombstone-handoff-kind-requalification.md"
require 'Admitted Predecessor Settlement' \
    "${root}/docs/adr/0242-admitted-predecessor-settlement.md"
require 'Immutable Admitted-Predecessor Kind Requalification' \
    "${root}/docs/adr/0243-immutable-admitted-predecessor-kind-requalification.md"
require 'EncryptionActivationPublicationOutcome::Superseded' \
    "${root}/bins/unf-agent/src/main.rs"
require 'ApiError::conflict' "${root}/bins/unf-controller/src/main.rs"
require 'discard_tombstoned_active_revalidation' \
    "${root}/bins/unf-agent/src/main.rs"
require 'must_settle_admitted_pending_before' \
    "${root}/bins/unf-agent/src/main.rs"
require 'unknown untombstoned key epoch' \
    "${root}/bins/unf-agent/src/main.rs"
require 'policyRevision:.active.fact.checkpoint.transaction.desired.published.policyRevision' \
    "${gate}"
require 'UNF_ENCRYPTION_BASELINE' "${overlay}/controller-native-patch.yaml"
require 'value: native' "${overlay}/controller-native-patch.yaml"
require 'UNF_ENCRYPTION_KEY_LIFETIME_SECONDS' "${overlay}/agent-rotation-patch.yaml"

controller_image=$(jq -er .images.controller "${release}")
agent_image=$(jq -er .images.agent "${release}")
grep -Fq "image: ${controller_image}" "${rendered}"
[[ $(grep -Fc "image: ${agent_image}" "${rendered}") == 2 ]]
grep -Fq 'value: native' "${rendered}"

if rg -q 'debug "node/' "${gate}"; then
    echo "Phase 9.9 host evidence must not create observer Pods per sample" >&2
    exit 1
fi
for bounded_wait in wait_generation_after wait_epoch_change; do
    wait_body=$(sed -n "/^${bounded_wait}()/,/^}/p" "${gate}")
    rg -q 'generation_snapshot' <<<"${wait_body}" || {
        echo "${bounded_wait} must inspect one direct generation snapshot per retry" >&2
        exit 1
    }
    if rg -q 'snapshot=\$\(wait_generation' <<<"${wait_body}"; then
        echo "${bounded_wait} must not nest the independent convergence timeout" >&2
        exit 1
    fi
done

for bounded_wait in wait_generation wait_generation_after wait_epoch_change; do
    wait_body=$(sed -n "/^${bounded_wait}()/,/^}/p" "${gate}")
    rg -q 'current_revision_cut' <<<"${wait_body}" || {
        echo "${bounded_wait} must join the current agent and egress revision cut" >&2
        exit 1
    }
    rg -q 'generation_matches_current_cut' <<<"${wait_body}" || {
        echo "${bounded_wait} must reject a stale encryption revision vector" >&2
        exit 1
    }
done

selective_line=$(rg -n '^stage=selective-native-exception$' "${gate}" | cut -d: -f1)
ciphertext_line=$(rg -n '^stage=ciphertext-and-fail-closed$' "${gate}" | cut -d: -f1)
evidence_line=$(rg -n '^stage=evidence$' "${gate}" | cut -d: -f1)
(( selective_line < ciphertext_line && ciphertext_line < evidence_line )) || {
    echo "selective qualification must execute before ciphertext and evidence emission" >&2
    exit 1
}

echo "Phase 9.9 OpenShift encryption qualification gate contract verified"
