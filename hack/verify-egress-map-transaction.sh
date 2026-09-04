#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
object=${UNF_EBPF_OBJECT:-${project_root}/ebpf/unf-ebpf-tc/target/bpfel-unknown-none/release/unf-ebpf-tc}
bpf_toolchain=${UNF_BPF_TOOLCHAIN:-nightly-2026-07-15}

command -v jq >/dev/null
command -v rg >/dev/null
sudo -n true

rg --fixed-strings --quiet \
    'pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = 15;' \
    "${project_root}/crates/unf-state/src/lib.rs"
rg --fixed-strings --quiet \
    'const PERSISTENT_MAP_NAMES: [&str; 40]' \
    "${project_root}/bins/unf-agent/src/main.rs"
rg --fixed-strings --quiet \
    '| Transactional persistent egress maps | **Verified** |' \
    "${project_root}/docs/project-status.md"

cargo +"${bpf_toolchain}" build \
    --manifest-path "${project_root}/ebpf/unf-ebpf-tc/Cargo.toml" \
    -Z build-std=core --target bpfel-unknown-none --release

cargo test -p unf-agent \
    egress_dataplane_encoding_is_exact_and_rejects_foreign_bank_entries

test_binary=$(cargo test -p unf-agent --no-run --message-format=json \
    | jq -r 'select(.profile.test == true and .target.name == "unf-agent") | .executable' \
    | tail -n 1)
[[ -n ${test_binary} && -x ${test_binary} ]]

sudo -n env UNF_EBPF_OBJECT="${object}" "${test_binary}" \
    --ignored --exact \
    tests::privileged_egress_bank_activation_rollback_and_recovery_are_exact

echo "Egress map transaction passed: ABI-v15 ownership, temporal destination readback, capacity rollback, and pointer recovery are exact"
