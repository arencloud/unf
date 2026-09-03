#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
object=${UNF_EBPF_OBJECT:-${project_root}/ebpf/unf-ebpf-tc/target/bpfel-unknown-none/release/unf-ebpf-tc}
bpf_toolchain=${UNF_BPF_TOOLCHAIN:-nightly-2026-07-15}

command -v jq >/dev/null
command -v rg >/dev/null
sudo -n true

rg --fixed-strings --quiet 'pub const EGRESS_MAP_ABI_VERSION: u16 = 3;' \
    "${project_root}/ebpf/unf-ebpf-common/src/lib.rs"
rg --fixed-strings --quiet 'pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = 14;' \
    "${project_root}/crates/unf-state/src/lib.rs"
rg --fixed-strings --quiet 'const PERSISTENT_MAP_NAMES: [&str; 40]' \
    "${project_root}/bins/unf-agent/src/main.rs"
rg --fixed-strings --quiet '| Collision-safe gateway SNAT and reverse state | **Verified** |' \
    "${project_root}/docs/project-status.md"

cargo +"${bpf_toolchain}" build \
    --manifest-path "${project_root}/ebpf/unf-ebpf-tc/Cargo.toml" \
    -Z build-std=core --target bpfel-unknown-none --release
cargo test -p unf-ebpf-common egress_snat_candidates_form_proof_salted_nonrepeating_cycles
cargo test -p unf-egress gateway_nat_bank_is_identity_namespaced_and_heterogeneous

test_binary=$(cargo test -p unf-agent --no-run --message-format=json \
    | jq -r 'select(.profile.test == true and .target.name == "unf-agent") | .executable' \
    | tail -n 1)
[[ -n ${test_binary} && -x ${test_binary} ]]

sudo -n env UNF_EBPF_OBJECT="${object}" "${test_binary}" \
    --ignored --exact \
    tests::privileged_egress_source_steering_is_policy_first_destination_exact_and_dual_stack

echo "Phase 8.5 gateway NAT passed: heterogeneous proof banks, full-cycle collision probing, dual-stack checksum-safe SNAT, exact reverse restoration, and first-flow preservation are verifier-proven"
