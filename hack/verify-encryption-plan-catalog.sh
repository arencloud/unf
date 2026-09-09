#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5t catalog ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

distribution=crates/unf-encryption/src/plan_distribution.rs
controller=bins/unf-controller/src/main.rs

require_text 'pub struct NodeLocalPlanFleetCut' "${distribution}"
require_text 'members: Vec<EncryptionGenerationRecipient>' "${distribution}"
require_text 'plans: Vec<NodeLocalPlanSnapshot>' "${distribution}"
require_text 'self\.members\.len\(\) != self\.plans\.len\(\)' "${distribution}"
require_text 'fleet plan causal revisions are mixed' "${distribution}"
require_text 'pub struct NodeLocalPlanCatalog' "${distribution}"
require_text 'same-generation equivocation' "${distribution}"
require_text 'fleet_synchronous_catalog_is_atomic_monotonic_and_equivocation_safe' \
  crates/unf-encryption/src/local_plan_compiler.rs
require_text 'Mutex<NodeLocalPlanCatalog>' "${controller}"
require_text '\.desired_for\(&recipient\)' "${controller}"
require_text 'Fleet-Synchronous Plan Cut' docs/adr/0181-fleet-synchronous-plan-cut.md

if ! grep -B 2 'pub struct NodeLocalPlanFleetCut {' "${distribution}" \
  | grep -q 'deny_unknown_fields'; then
  echo "fleet plan cuts must reject unknown fields" >&2
  exit 1
fi

echo "Phase 9.5t fleet plan cut passed: exact membership plans publish atomically with monotonic equivocation-safe visibility"
