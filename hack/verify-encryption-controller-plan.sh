#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

controller=bins/unf-controller/src/main.rs
for pattern in \
  'struct EncryptionPlanSource' \
  'struct EncryptionPlanReconciler' \
  'fn policy_sample_ports' \
  'fn encryption_policy_observations' \
  'fn join_encryption_plan_recovery_cursor' \
  'fn reconcile_encryption_plan_catalog_at' \
  'produce_fleet_plan_cut' \
  'restored_encryption_plan_waits_for_one_complete_fleet_cursor_cut' \
  'encryption_plan_poll_projects_one_causal_catalog_and_coalesces_retries'; do
  rg -q "${pattern}" "${controller}" || {
    echo "missing required Phase 9.5ab controller plan runtime ${pattern@Q}" >&2
    exit 1
  }
done
rg -q 'Pull-Synchronized Causal Catalog' \
  docs/adr/0189-pull-synchronized-causal-catalog.md
rg -q 'Complete Fleet Cursor Recovery Barrier' \
  docs/adr/0224-complete-fleet-cursor-recovery-barrier.md

echo "Phase 9.5ab controller plan runtime passed: one revision cut is projected, coalesced, restart-joined, fleet-published, and delivered only to its authenticated Node UID"
