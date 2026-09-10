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
    echo "missing required Phase 9.5ae composition ${pattern@Q} in ${path}" >&2
    exit 1
  }
}

require_text 'SERVICE_CONNECTION_FLAG_ENCRYPTED_NAT' ebpf/unf-ebpf-common/src/lib.rs
require_text 'fn secure_dsr_service_translation' ebpf/unf-ebpf-tc/src/main.rs
require_text 'external egress ownership must not borrow a Pod transport lease' bins/unf-agent/src/main.rs
require_text 'revocation terminates an established Required lease' bins/unf-agent/src/main.rs
require_text 'Flow-Adaptive Secure DSR' docs/adr/0192-flow-adaptive-secure-dsr.md

command -v jq >/dev/null
sudo -n true
cargo +"${bpf_toolchain}" build --manifest-path ebpf/unf-ebpf-tc/Cargo.toml \
  -Z build-std=core --target bpfel-unknown-none --release
cargo test -p unf-ebpf-common service_connections_expire_without_following_desired_state_revisions
cargo clippy -p unf-ebpf-common -p unf-agent --all-targets --all-features -- -D warnings

test_binary=$(cargo test -p unf-agent --no-run --message-format=json \
  | jq -r 'select(.profile.test == true and .target.name == "unf-agent") | .executable' \
  | tail -n 1)
[[ -n ${test_binary} && -x ${test_binary} ]]

for test_name in \
  privileged_encryption_finalizer_is_dual_stack_late_bound_and_fail_closed \
  privileged_egress_source_steering_is_policy_first_destination_exact_and_dual_stack \
  privileged_load_balancer_dsr_preserves_dual_stack_vips_and_direct_return
do
  sudo -n env UNF_EBPF_OBJECT="${object}" "${test_binary}" --ignored --exact \
    "tests::${test_name}"
done

echo "Phase 9.5ae composition passed: bounded rotation/revocation, egress precedence, Native DSR, and per-flow secure DSR-to-NAT transition"
