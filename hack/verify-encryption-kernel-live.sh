#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_interface=${UNF_WIREGUARD_TEST_INTERFACE:-unfwgtest9}
foreign_test_interface=${UNF_WIREGUARD_FOREIGN_TEST_INTERFACE:-unfwgfrn9}

[[ ${test_interface} =~ ^unfwg[a-zA-Z0-9-]{0,10}$ ]] || {
    echo "invalid dedicated WireGuard test interface: ${test_interface}" >&2
    exit 1
}
[[ ${foreign_test_interface} =~ ^unfwg[a-zA-Z0-9-]{0,10}$ ]] || {
    echo "invalid dedicated foreign-route test interface: ${foreign_test_interface}" >&2
    exit 1
}
[[ ${test_interface} != "${foreign_test_interface}" ]] || {
    echo "kernel test interfaces must be distinct" >&2
    exit 1
}
command -v jq >/dev/null 2>&1 || {
    echo "jq is required to resolve the Rust test executable" >&2
    exit 1
}
sudo -n true >/dev/null || {
    echo "passwordless sudo or CAP_NET_ADMIN is required for the live kernel gate" >&2
    exit 1
}

cleanup() {
    local interface
    for interface in "${test_interface}" "${foreign_test_interface}"; do
        if ip link show "${interface}" >/dev/null 2>&1; then
            sudo -n ip link del "${interface}"
        fi
    done
}
trap cleanup EXIT
cleanup

test_binary=$(
    cd "${project_root}"
    cargo test -p unf-encryption --no-run --message-format=json 2>/dev/null |
        jq -r 'select(.profile.test == true and .target.name == "unf_encryption") | .executable' |
        tail -1
)
[[ -n ${test_binary} && -x ${test_binary} ]] || {
    echo "unable to resolve the unf-encryption test executable" >&2
    exit 1
}

sudo -n env "UNF_WIREGUARD_TEST_INTERFACE=${test_interface}" \
    "UNF_WIREGUARD_FOREIGN_TEST_INTERFACE=${foreign_test_interface}" \
    "${test_binary}" \
    kernel_provider::linux::tests::privileged_kernel_stage_readback_rollback_and_cleanup_are_exact \
    --ignored --exact --nocapture

echo "Phase 9.4 live kernel provider passed: injected rollback, foreign preservation, exact dual-stack readback, replay, partial-owned retirement, restart rollback, and cleanup are verified"
