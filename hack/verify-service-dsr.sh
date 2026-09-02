#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
object=${UNF_EBPF_OBJECT:-${project_root}/ebpf/unf-ebpf-tc/target/bpfel-unknown-none/release/unf-ebpf-tc}
bpf_toolchain=${UNF_BPF_TOOLCHAIN:-nightly-2026-07-15}

command -v jq >/dev/null
command -v llvm-objdump >/dev/null
command -v rg >/dev/null
sudo -n true

dataplane=${project_root}/ebpf/unf-ebpf-tc/src/main.rs
agent=${project_root}/bins/unf-agent/src/main.rs
rg --fixed-strings --quiet 'let redirect_ifindex = lookup.ifindex;' "${dataplane}"
rg --fixed-strings --quiet 'if dsr && !normalize_service_dsr_vlan(ctx, lookup)' "${dataplane}"
rg --fixed-strings --quiet \
    'static mut SERVICE_DSR_TRANSPORT_INTERFACES: [u32; 4] = [0; 4];' "${dataplane}"
rg --fixed-strings --quiet \
    'core::ptr::read_volatile(core::ptr::addr_of!(' "${dataplane}"
rg --fixed-strings --quiet 'service_dsr_transport_interface(lookup)' "${dataplane}"
rg --fixed-strings --quiet \
    'redirect_service_dsr_neighbor(lookup)' "${dataplane}"
rg --fixed-strings --quiet \
    'bpf_redirect_neigh(' "${dataplane}"
rg --fixed-strings --quiet \
    'if !service_dsr_transport_ifindex(skb.ifindex)' "${dataplane}"
rg --fixed-strings --quiet 'bpf_skb_vlan_pop(ctx.skb.skb.cast()) == 0' "${dataplane}"
rg --fixed-strings --quiet \
    '"SERVICE_DSR_TRANSPORT_INTERFACES",' "${agent}"
rg --fixed-strings --quiet \
    'service_dsr_transport_interfaces_at(' "${agent}"
if rg --fixed-strings --quiet 'bpf_skb_vlan_push' "${dataplane}"; then
    echo "DSR must preserve the FIB route-device egress and its checksum/VLAN contract" >&2
    exit 1
fi

cargo +"${bpf_toolchain}" build --manifest-path "${project_root}/ebpf/unf-ebpf-tc/Cargo.toml" \
    -Z build-std=core --target bpfel-unknown-none --release
if ! llvm-objdump -d "${object}" | rg --count 'call 0x98' >/dev/null; then
    echo "compiled DSR dataplane does not retain bpf_redirect_neigh" >&2
    exit 1
fi
cargo test -p unf-agent dsr_transport_interfaces_include_only_a_confirmed_vlan_lower_link

test_binary=$(cargo test -p unf-agent --no-run --message-format=json \
    | jq -r 'select(.profile.test == true and .target.name == "unf-agent") | .executable' \
    | tail -n 1)
[[ -n ${test_binary} && -x ${test_binary} ]]

sudo -n env UNF_EBPF_OBJECT="${object}" "${test_binary}" --ignored
