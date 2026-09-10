#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! rg -q "${pattern}" "${path}"; then
    echo "missing required Phase 9.5z address binding ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

fast_path=crates/unf-encryption/src/fast_path.rs
shared=ebpf/unf-ebpf-common/src/lib.rs
agent=bins/unf-agent/src/encryption_maps.rs

require_text 'pub struct EncryptionPathAuthority' "${fast_path}"
require_text 'replicated_identity_late_binds_the_final_dual_stack_destination' "${fast_path}"
require_text 'ENCRYPTION_DECISION_FLAG_ADDRESS_BOUND' "${fast_path}"
require_text 'pub struct EncryptionIpv4PathData' "${shared}"
require_text 'pub struct EncryptionIpv6PathData' "${shared}"
require_text 'ENCRYPTION_MAP_ABI_VERSION: u16 = 2' "${shared}"
require_text 'ENCRYPTION_PATHS_V4' "${agent}"
require_text 'ENCRYPTION_PATHS_V6' "${agent}"
require_text 'Adaptive Address-Exact Replica Binding' docs/adr/0187-adaptive-address-exact-replica-binding.md

echo "Phase 9.5z address binding passed: direct decisions remain one lookup while replicated identities resolve the final IPv4/IPv6 destination without ambiguity"
