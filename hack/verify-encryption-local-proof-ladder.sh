#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5l contract ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

require_text 'pub struct NodeLocalGenerationProposal' crates/unf-encryption/src/local_orchestrator.rs
require_text 'pub struct ControllerAdmittedLocalGeneration' crates/unf-encryption/src/local_orchestrator.rs
require_text 'self,' crates/unf-encryption/src/local_orchestrator.rs
require_text 'admitted\.checkpoint != self\.fact\.checkpoint' crates/unf-encryption/src/local_orchestrator.rs
require_text 'EncryptionActivationLatch::issue' crates/unf-encryption/src/local_orchestrator.rs
require_text 'pub\(crate\) fn issue' crates/unf-encryption/src/activation_latch.rs
require_text '#\[derive\(Debug, PartialEq, Eq\)\]' crates/unf-encryption/src/route_authority.rs
require_text 'causal_proof_ladder_refuses_controller_substitution_and_reuse' crates/unf-encryption/src/fast_path.rs
require_text 'Capability-Typed Causal Proof Ladder' docs/adr/0173-capability-typed-causal-proof-ladder.md
require_text 'encryption-local-proof-ladder-test' docs/project-status.md

for capability in ControllerAdmittedLocalGeneration LinuxPreparedLocalGeneration; do
  if grep -B 3 "pub struct ${capability} {" crates/unf-encryption/src/local_orchestrator.rs \
    | grep -Eq 'derive\([^)]*(Serialize|Deserialize|Clone)[^)]*\)'; then
    echo "Node-local proof capability ${capability} must not be cloneable or serializable" >&2
    exit 1
  fi
done

if grep -Eq 'permit\.clone\(\)' crates/unf-encryption/src/fast_path.rs; then
  echo "route publication permits must remain consuming capabilities" >&2
  exit 1
fi

permit_derive=$(awk \
  '/pub struct EncryptionRoutePublicationPermit \{/{print previous} {previous=$0}' \
  crates/unf-encryption/src/route_authority.rs)
if [[ ${permit_derive} != '#[derive(Debug, PartialEq, Eq)]' ]]; then
  echo "route publication permits must be non-cloneable and non-serializable" >&2
  exit 1
fi

echo "Phase 9.5l proof ladder passed: exact proposal, controller admission, local route proof, and Aya activation are consuming capabilities"
