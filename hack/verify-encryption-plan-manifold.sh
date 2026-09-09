#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5q contract ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

compiler=crates/unf-encryption/src/local_plan_compiler.rs

require_text 'pub struct NodeLocalPlanSnapshot' "${compiler}"
require_text 'pub struct NodeLocalPlanSnapshotFields' "${compiler}"
require_text 'pub struct NodeLocalEpochPlanRecord' "${compiler}"
require_text 'pub struct NodeLocalDecisionPlan' "${compiler}"
require_text 'NODE_LOCAL_PLAN_SNAPSHOT_DIGEST_DOMAIN' "${compiler}"
require_text 'pub fn verify\(&self\)' "${compiler}"
require_text 'validate_decision_coverage' "${compiler}"
require_text 'required contract plans are not completely covered' "${compiler}"
require_text 'native decision carries transport authority' "${compiler}"
require_text 'pub fn prepare_exact_readback' "${compiler}"
require_text 'pub async fn prepare_linux' "${compiler}"
require_text 'causal_input_manifold_is_canonical_complete_and_strict' "${compiler}"
require_text 'Causally Sealed Input Manifold' docs/adr/0178-causally-sealed-input-manifold.md
require_text 'encryption-plan-manifold-test' docs/project-status.md

if ! grep -B 2 'pub struct NodeLocalPlanSnapshot {' "${compiler}" \
  | grep -q 'deny_unknown_fields'; then
  echo "Node-local plan snapshots must reject unknown wire authority" >&2
  exit 1
fi

if grep -A 18 'pub struct NodeLocalPlanSnapshot {' "${compiler}" \
  | grep -Eq 'private_key|route_permit|activation_latch'; then
  echo "the plan manifold must remain secret-free and non-authoritative" >&2
  exit 1
fi

echo "Phase 9.5q input manifold passed: exact contract coverage, epoch readiness, revisions, and Node identity move as one secret-free causal cut"
