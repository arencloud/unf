#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5o contract ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

agent=bins/unf-agent/src/main.rs
orchestrator=crates/unf-encryption/src/local_orchestrator.rs

require_text 'pub struct NodeLocalRecoveryPlan' "${orchestrator}"
require_text 'RECOVERY_PLAN_DIGEST_DOMAIN' "${orchestrator}"
require_text 'pub fn rehydrate_exact_readback' "${orchestrator}"
require_text 'pub async fn rehydrate_linux' "${orchestrator}"
require_text '\.readback\(plan\)' "${orchestrator}"
require_text 'fn encryption_recovery_plan_path' "${agent}"
require_text 'active: Option<NodeLocalRecoveryPlan>' "${agent}"
require_text 'pending: Option<NodeLocalRecoveryPlan>' "${agent}"
require_text 'fn select_encryption_recovery_slot' "${agent}"
require_text 'prepared\.recovery_plan\(\)' "${agent}"
require_text 'async fn rehydrate_local_proof' "${agent}"
require_text 'async fn activate_admitted_encryption_generation' "${agent}"
require_text 'fn active_path_proof_state' "${agent}"
require_text 'async fn assist_active_encryption_path_proofs' "${agent}"
require_text 'active\.fact\.checkpoint != admitted\.checkpoint' "${agent}"
require_text 'missing_assignments' "${agent}"
require_text 'participate in current active-generation path proof rounds' "${agent}"
require_text 'let _ = collect_live_encryption_path_receipts' "${agent}"
require_text 'rehydrate_local_proof\([^)]*\)\.await\?' "${agent}"
require_text 'requires a fresh Node-local tri-plane activation latch before TC attachment' "${agent}"
require_text 'recovery_plan_rehydrates_fresh_capability_and_rejects_serialized_authority' crates/unf-encryption/src/fast_path.rs
require_text 'encryption_recovery_plan_is_owner_only_and_fail_closed' "${agent}"
require_text 'encryption_recovery_slot_prioritizes_admitted_successor_then_current' "${agent}"
require_text 'Proof-Rehydrating Activation Escrow' docs/adr/0176-proof-rehydrating-activation-escrow.md
require_text 'Reciprocal Active-Generation Proof Service' docs/adr/0216-reciprocal-active-generation-proof-service.md
require_text 'encryption-activation-rehydration-test' docs/project-status.md

rehydrate_line="$(grep -nE 'rehydrate_local_proof\([^)]*\)\.await\?' "${agent}" | head -1 | cut -d: -f1)"
attach_line="$(grep -n 'let mut attachments = attach_dataplane_programs' "${agent}" | head -1 | cut -d: -f1)"
if (( rehydrate_line >= attach_line )); then
  echo "fresh local proof must be reconstructed before TC attachment" >&2
  exit 1
fi

if grep -B 2 'pub struct LinuxPreparedLocalGeneration {' "${orchestrator}" \
  | grep -Eq 'Serialize|Deserialize|Clone'; then
  echo "rehydration must not make the local activation capability serializable or cloneable" >&2
  exit 1
fi

echo "Phase 9.5o activation rehydration passed: a secret-free plan can recreate fresh exact Linux proof, but never serialized activation authority, before Aya recovery and TC attachment"
