#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5p contract ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

compiler=crates/unf-encryption/src/local_plan_compiler.rs

require_text 'pub struct NodeLocalPlanCompileContext' "${compiler}"
require_text 'pub struct NodeLocalEpochPlan' "${compiler}"
require_text 'pub fn compile_exact_readback' "${compiler}"
require_text 'pub async fn compile_and_stage_linux' "${compiler}"
require_text 'key_authority\.private_key_for_kernel_plan' "${compiler}"
require_text 'provider\.apply\(plan, private_key\)' "${compiler}"
require_text 'ProofCarryingKernelTransaction::begin' "${compiler}"
require_text 'transaction\.commit\(snapshot\)' "${compiler}"
require_text 'compile_encryption_fast_path' "${compiler}"
require_text 'FastPathMapCheckpoint::begin' "${compiler}"
require_text 'snapshot_first_compiler_coalesces_identity_cartesian_product_to_one_peer' "${compiler}"
require_text 'snapshot_first_compiler_refuses_partial_or_cross_node_authority' "${compiler}"
require_text 'Snapshot-First Causal Plan Compiler' docs/adr/0177-snapshot-first-causal-plan-compiler.md
require_text 'encryption-local-plan-compiler-test' docs/project-status.md

key_line="$(grep -n 'private_key_for_kernel_plan' "${compiler}" | head -1 | cut -d: -f1)"
apply_line="$(grep -n 'provider.apply(plan, private_key)' "${compiler}" | head -1 | cut -d: -f1)"
compile_line="$(grep -n 'Self::compile_exact_readback' "${compiler}" | head -1 | cut -d: -f1)"
if (( key_line >= apply_line || apply_line >= compile_line )); then
  echo "all keys must preflight before kernel staging, and exact readback must precede map compilation" >&2
  exit 1
fi

if grep -Eq 'private_key|WireGuardPrivateKey' docs/adr/0177-snapshot-first-causal-plan-compiler.md \
  && ! grep -Eq 'never persists|never serializes|not persisted' docs/adr/0177-snapshot-first-causal-plan-compiler.md; then
  echo "the compiler ADR must make private-key non-persistence explicit" >&2
  exit 1
fi

echo "Phase 9.5p local plan compiler passed: identity-exact decisions coalesce to one snapshot-first Node peer per epoch without serialized key authority"
