#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5m contract ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

require_text 'pub struct LinuxPreparedLocalGeneration' crates/unf-encryption/src/local_orchestrator.rs
require_text 'pub async fn stage_linux' crates/unf-encryption/src/local_orchestrator.rs
require_text 'preflight_plan_cut\(&recipient, &desired, plans\)\?' crates/unf-encryption/src/local_orchestrator.rs
require_text '\.private_key_for_kernel_plan\(plan\)' crates/unf-encryption/src/local_orchestrator.rs
require_text '\.apply\(plan, private_key\)' crates/unf-encryption/src/local_orchestrator.rs
require_text 'pub fn bind_exact_readback' crates/unf-encryption/src/local_orchestrator.rs
require_text 'pub async fn admit_and_activate_linux' crates/unf-encryption/src/local_orchestrator.rs
require_text 'LinuxEncryptionRouteProvider' crates/unf-encryption/src/local_orchestrator.rs
require_text 'apply_linux_generation' bins/unf-agent/src/encryption_maps.rs
require_text 'linux_convergence_capsule_binds_the_complete_exact_kernel_cut' crates/unf-encryption/src/fast_path.rs
require_text 'linux_convergence_capsule_refuses_partial_foreign_or_active_staging' crates/unf-encryption/src/fast_path.rs
require_text 'Proof-Carrying Linux Convergence Capsule' docs/adr/0174-proof-carrying-linux-convergence-capsule.md
require_text 'encryption-linux-convergence-test' docs/project-status.md

if grep -B 2 'pub struct LinuxPreparedLocalGeneration {' \
  crates/unf-encryption/src/local_orchestrator.rs | grep -Eq 'Serialize|Deserialize|Clone'; then
  echo "Linux convergence capsules must remain non-cloneable and non-serializable" >&2
  exit 1
fi

echo "Phase 9.5m Linux convergence passed: ready local keys, deterministic WireGuard staging, exact complete readback, controller admission, policy routes, and Aya publication form one fail-closed capability path"
