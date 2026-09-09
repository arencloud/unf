#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5r contract ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

distribution=crates/unf-encryption/src/plan_distribution.rs

require_text 'pub struct NodeLocalPlanRequest' "${distribution}"
require_text 'pub struct NodeLocalPlanCursor' "${distribution}"
require_text 'pub struct NodeSealedPlanCapsule' "${distribution}"
require_text 'pub struct AdmittedNodeLocalPlan' "${distribution}"
require_text 'request_nonce' "${distribution}"
require_text 'snapshot: NodeLocalPlanSnapshot' "${distribution}"
require_text 'snapshot\.generation <= current\.generation' "${distribution}"
require_text 'pub fn admit' "${distribution}"
require_text 'Node-sealed plan capsule does not answer the exact request' "${distribution}"
require_text 'node_sealed_plan_delivery_is_nonce_bound_monotonic_and_non_authoritative' \
  crates/unf-encryption/src/local_plan_compiler.rs
require_text 'Nonce-Bound Plan Relay' docs/adr/0179-nonce-bound-plan-relay.md

if grep -Eq 'private_key|route_permit|activation_latch' "${distribution}"; then
  echo "plan delivery must not serialize local activation authority" >&2
  exit 1
fi

for object in NodeLocalPlanRequest NodeLocalPlanCursor NodeSealedPlanCapsule AdmittedNodeLocalPlan; do
  if ! grep -B 2 "pub struct ${object} {" "${distribution}" | grep -q 'deny_unknown_fields'; then
    echo "${object} must reject unknown wire authority" >&2
    exit 1
  fi
done

echo "Phase 9.5r plan relay passed: nonce-bound exact-predecessor delivery is monotonic, Node-scoped, strict, and non-authoritative"
