#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
object=${UNF_EBPF_OBJECT:-${project_root}/ebpf/unf-ebpf-tc/target/bpfel-unknown-none/release/unf-ebpf-tc}
bpf_toolchain=${UNF_BPF_TOOLCHAIN:-nightly-2026-07-15}

command -v jq >/dev/null
command -v rg >/dev/null
sudo -n true

rg --fixed-strings --quiet 'pub const EGRESS_MAP_ABI_VERSION: u16 = 4;' \
    "${project_root}/ebpf/unf-ebpf-common/src/lib.rs"
rg --fixed-strings --quiet 'pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = 15;' \
    "${project_root}/crates/unf-state/src/lib.rs"
rg --fixed-strings --quiet '| Autonomous PLR observation and enforcement | **Verified** |' \
    "${project_root}/docs/project-status.md"
rg --fixed-strings --quiet '| 8.7c | Autonomous PLR observation and enforcement | **Verified** |' \
    "${project_root}/docs/development/phase8-egress-fabric-plan.md"
rg --fixed-strings --quiet '**Status:** Accepted and implemented for Phase 8 milestone 8.7c' \
    "${project_root}/docs/adr/0144-autonomous-dual-clock-plr-enforcement.md"

cargo +"${bpf_toolchain}" build \
    --manifest-path "${project_root}/ebpf/unf-ebpf-tc/Cargo.toml" \
    -Z build-std=core --target bpfel-unknown-none --release
cargo test -p unf-egress durable_ledger_materializes_one_quorum_snapshot_and_empty_withdraws_it
cargo test -p unf-egress plr_snapshot_lowers_to_exact_temporal_authority_plus_dual_stack_deny
cargo test -p unf-agent fqdn_observer::tests
cargo test -p unf-controller authenticated_fqdn_observation_batches_are_durable_monotonic_and_node_bound

test_binary=$(cargo test -p unf-agent --no-run --message-format=json \
    | jq -r 'select(.profile.test == true and .target.name == "unf-agent") | .executable' \
    | tail -n 1)
[[ -n ${test_binary} && -x ${test_binary} ]]

sudo -n env UNF_EBPF_OBJECT="${object}" "${test_binary}" \
    --ignored --exact \
    tests::privileged_egress_source_steering_is_policy_first_destination_exact_and_dual_stack

echo "Phase 8.7c FQDN dataplane passed: bounded DNS evidence, transactional PLR banks, and dual-clock autonomous new/established-flow expiry are verifier-proven"
