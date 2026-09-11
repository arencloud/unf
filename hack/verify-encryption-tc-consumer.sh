#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

bpf_toolchain=${UNF_BPF_TOOLCHAIN:-nightly-2026-07-15}
object=${UNF_EBPF_OBJECT:-${root_dir}/ebpf/unf-ebpf-tc/target/bpfel-unknown-none/release/unf-ebpf-tc}

require_text() {
  local pattern="$1"
  local path="$2"
  rg -q "${pattern}" "${path}" || {
    echo "missing required Phase 9.5ad TC consumer ${pattern@Q} in ${path}" >&2
    exit 1
  }
}

require_text 'fn apply_encryption_selection' ebpf/unf-ebpf-tc/src/main.rs
require_text 'fn encryption_finalizer' ebpf/unf-ebpf-tc/src/main.rs
require_text 'ENCRYPTION_CONNECTIONS' ebpf/unf-ebpf-tc/src/main.rs
require_text 'Identity-Scoped Packet-Mark Ownership' ebpf/unf-ebpf-tc/src/main.rs
require_text 'privileged_encryption_finalizer_is_dual_stack_late_bound_and_fail_closed' bins/unf-agent/src/main.rs
require_text 'an unmanaged physical-uplink flow must preserve foreign host mark ownership byte-for-byte' bins/unf-agent/src/main.rs
require_text 'Proof-Carrying Deferred Encryption' docs/adr/0191-proof-carrying-deferred-encryption.md
require_text 'Identity-Scoped Packet-Mark Ownership' docs/adr/0220-identity-scoped-packet-mark-ownership.md

command -v jq >/dev/null
sudo -n true
cargo +"${bpf_toolchain}" build --manifest-path ebpf/unf-ebpf-tc/Cargo.toml \
  -Z build-std=core --target bpfel-unknown-none --release
cargo test -p unf-ebpf-common encryption_packet_authority_is_exact_revision_bound_and_temporal
cargo clippy -p unf-ebpf-common -p unf-agent --all-targets --all-features -- -D warnings

test_binary=$(cargo test -p unf-agent --no-run --message-format=json \
  | jq -r 'select(.profile.test == true and .target.name == "unf-agent") | .executable' \
  | tail -n 1)
[[ -n ${test_binary} && -x ${test_binary} ]]

sudo -n env UNF_EBPF_OBJECT="${object}" "${test_binary}" --ignored --exact \
  tests::privileged_pinned_tail_call_map_survives_agent_owner_exit
sudo -n env UNF_EBPF_OBJECT="${object}" "${test_binary}" --ignored --exact \
  tests::privileged_encryption_finalizer_is_dual_stack_late_bound_and_fail_closed

echo "Phase 9.5ad TC consumer passed: policy-first final-tuple selection, identity-scoped mark ownership, dual-stack late binding, flow-stable leases, verifier loading, and Required fail-closed behavior"
