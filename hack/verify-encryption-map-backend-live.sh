#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
object=${UNF_EBPF_OBJECT:-${project_root}/ebpf/unf-ebpf-tc/target/bpfel-unknown-none/release/unf-ebpf-tc}

command -v jq >/dev/null 2>&1 || {
    echo "jq is required to resolve the Rust test executable" >&2
    exit 1
}
sudo -n true >/dev/null || {
    echo "passwordless sudo or BPF capabilities are required for the live Aya map gate" >&2
    exit 1
}
[[ -f ${object} ]] || {
    echo "compiled eBPF object is missing: ${object}" >&2
    exit 1
}

test_binary=$(
    cd "${project_root}"
    cargo test -p unf-agent --no-run --message-format=json 2>/dev/null |
        jq -r 'select(.profile.test == true and .target.name == "unf-agent") | .executable' |
        tail -1
)
[[ -n ${test_binary} && -x ${test_binary} ]] || {
    echo "unable to resolve the unf-agent test executable" >&2
    exit 1
}

sudo -n env "UNF_EBPF_OBJECT=${object}" \
    "${test_binary}" \
    encryption_maps::tests::privileged_aya_island_opens_with_exact_shapes_and_quiescent_recovery \
    --ignored --exact --nocapture

echo "Phase 9.5d live Aya backend passed: the kernel accepted all fixed map shapes and fresh-map recovery remained quiescent"
