#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
object=${UNF_EBPF_OBJECT:-${project_root}/ebpf/unf-ebpf-tc/target/bpfel-unknown-none/release/unf-ebpf-tc}
bpf_toolchain=${UNF_BPF_TOOLCHAIN:-nightly-2026-07-15}

command -v jq >/dev/null
sudo -n true

cargo +"${bpf_toolchain}" build --manifest-path "${project_root}/ebpf/unf-ebpf-tc/Cargo.toml" \
    -Z build-std=core --target bpfel-unknown-none --release

test_binary=$(cargo test -p unf-agent --no-run --message-format=json \
    | jq -r 'select(.profile.test == true and .target.name == "unf-agent") | .executable' \
    | tail -n 1)
[[ -n ${test_binary} && -x ${test_binary} ]]

sudo -n env UNF_EBPF_OBJECT="${object}" "${test_binary}" \
    --ignored --exact \
    tests::privileged_load_balancer_cluster_packets_translate_dual_stack_and_survive_churn

# Preserve the verified NodePort and ClusterIP paths while adding VIP lookup
# ahead of the host-facing fallback.
sudo -n env UNF_EBPF_OBJECT="${object}" "${test_binary}" \
    --ignored --exact \
    tests::privileged_node_port_cluster_and_local_packets_translate_dual_stack_and_survive_churn

sudo -n env UNF_EBPF_OBJECT="${object}" "${test_binary}" \
    --ignored --exact \
    tests::privileged_service_packets_translate_dual_stack_and_survive_churn
