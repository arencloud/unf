#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 9.4" >&2
    exit 1
}

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 9.4 file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.4 check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text docs/project-status.md \
    '| Transactional kernel WireGuard provider | **Verified** |' \
    "the authoritative tracker must verify milestone 9.4"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    '| 9.4 | Transactional kernel WireGuard provider | **Verified** |' \
    "the execution plan must verify milestone 9.4"
require_text docs/adr/0161-proof-carrying-kernel-wireguard-transactions.md \
    '**Status:** Accepted and implemented for Phase 9.4' \
    "ADR 0161 must record the accepted implementation"
require_text Cargo.toml \
    'netlink-packet-wireguard = "0.5.0"' \
    "WireGuard configuration must use the typed generic-netlink packet model"
require_text crates/unf-encryption/src/kernel_provider.rs \
    'pub struct ProofCarryingKernelTransaction {' \
    "restart recovery must carry exact before/desired/readback proof"
require_text crates/unf-encryption/src/kernel_provider.rs \
    'prefixes.windows(2).any(|pair| pair[0].overlaps(pair[1]))' \
    "AllowedIP overlap validation must remain sorted rather than quadratic"
require_text crates/unf-encryption/src/kernel_provider/linux.rs \
    'WireguardDeviceFlags::ReplacePeers' \
    "peer replacement must be one exact bounded set"
require_text crates/unf-encryption/src/kernel_provider/linux.rs \
    'pub async fn rollback_prepared(' \
    "restart rollback must require a verified prepared checkpoint"
require_text crates/unf-encryption/src/kernel_provider/linux.rs \
    'is_kernel_generated_wireguard_multicast' \
    "exact route readback must narrowly account for kernel-generated multicast"
require_text crates/unf-encryption/src/kernel_provider/linux.rs \
    'private_bytes.zeroize();' \
    "the provider's direct private-key copy must be zeroized"
require_text crates/unf-encryption/src/kernel_provider/linux.rs \
    'privileged_kernel_stage_readback_rollback_and_cleanup_are_exact' \
    "the real-kernel lifecycle must remain available as a focused test"
require_text crates/unf-encryption/src/kernel_provider/linux.rs \
    'validate_monotonic_retirement_boundary' \
    "partial owned retirement must use its dedicated subset proof"
require_text crates/unf-encryption/src/kernel_provider/linux.rs \
    'retiring WireGuard epoch has an unplanned peer' \
    "retirement must refuse peer authority outside the signed plan"
require_text bins/unf-agent/src/main.rs \
    'before asking Route-Before-Authority to mint a permit' \
    "proof-time repair must precede route-permit issuance"

repair_line=$(rg -n 'repair_controller_admitted_kernel\(key_authority\)' \
    "${project_root}/bins/unf-agent/src/main.rs" | tail -1 | cut -d: -f1)
permit_line=$(rg -n 'generations\.ensure_probe_routes\(\)\.await' \
    "${project_root}/bins/unf-agent/src/main.rs" | tail -1 | cut -d: -f1)
if [[ -z ${repair_line} || -z ${permit_line} || ${repair_line} -ge ${permit_line} ]]; then
    echo "Phase 9.4 check failed: admitted kernel repair must precede route-permit issuance" >&2
    exit 1
fi

if rg --quiet '#\[allow' \
    "${project_root}/crates/unf-encryption/src/kernel_provider.rs" \
    "${project_root}/crates/unf-encryption/src/kernel_provider/linux.rs"; then
    echo "Phase 9.4 check failed: kernel provider must not suppress lint findings" >&2
    exit 1
fi

echo "Phase 9.4 kernel provider passed: typed netlink, proof-carrying recovery, exact readback, bounded reconciliation, monotonic retirement, foreign-state refusal, MTU, and cleanup agree"
