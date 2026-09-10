#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5x fleet producer ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

producer=crates/unf-encryption/src/fleet_plan_producer.rs
compiler=crates/unf-encryption/src/local_plan_compiler.rs

require_text 'pub struct FleetPlanProductionInput' "${producer}"
require_text 'pub fn produce_fleet_plan_cut' "${producer}"
require_text 'derive_ready_key_facts' "${producer}"
require_text 'KeyEpochPhase::MutuallyAttested' "${producer}"
require_text 'NodeLocalPlanMode::Dormant' "${producer}"
require_text 'NodeLocalPlanFleetCut::issue' "${producer}"
require_text 'demand_sparse_plan_cut_is_atomic_and_keeps_idle_nodes_dormant' "${producer}"
require_text 'fleet_plan_production_refuses_any_unattested_member' "${producer}"

require_text 'NODE_LOCAL_PLAN_SNAPSHOT_SCHEMA_VERSION: u16 = 2' "${compiler}"
require_text 'pub enum NodeLocalPlanMode' "${compiler}"
require_text 'dormant Node-local plan carries transport authority' "${compiler}"
require_text 'Demand-Sparse Fleet Plan Forge' docs/adr/0185-demand-sparse-fleet-plan-forge.md

if grep -Eq 'WireGuardPrivateKey|private_key_for_kernel|expose_for_kernel' "${producer}"; then
  echo "fleet plan producer must remain public-fact-only" >&2
  exit 1
fi

echo "Phase 9.5x fleet producer passed: one causal ready-key cut yields atomic active plans and authority-free dormant members"
