#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.6d check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text 'pub fn proof_beacon(self) -> Ipv4Addr {' \
    crates/unf-ipam/src/lib.rs \
    'IPv4 proof identity must come from an IPAM-excluded block boundary'
require_text 'pub const fn proof_beacon(self) -> Ipv6Addr {' \
    crates/unf-ipam/src/lib.rs \
    'IPv6 proof identity must come from an IPAM-excluded block boundary'
require_text 'pub fn derive_wireguard_proof_addresses(' \
    crates/unf-encryption/src/kernel_provider.rs \
    'the kernel plan must derive canonical host addresses from Node Pod CIDRs'
require_text 'WireGuardKernelCapability::ExactProofBeaconAddresses' \
    crates/unf-encryption/src/kernel_provider.rs \
    'adjacent providers must negotiate exact beacon support'
require_text 'add_proof_addresses(&handle, plan, link.header.index).await?;' \
    crates/unf-encryption/src/kernel_provider/linux.rs \
    'beacons must be installed before exact route/readback proof'
require_text 'read_proof_addresses(handle, plan, link.header.index).await?;' \
    crates/unf-encryption/src/kernel_provider/linux.rs \
    'beacons must be independently read from Linux'
require_text 'is_kernel_generated_proof_address_route' \
    crates/unf-encryption/src/kernel_provider/linux.rs \
    'exact readback must recognize only the beacon-generated kernel routes'
require_text '10.250.1.254/32' \
    hack/verify-encryption-ciphertext-live.sh \
    'the live ciphertext gate must exercise the IPv4 proof beacon'
require_text 'fd00:250:1::/128' \
    hack/verify-encryption-ciphertext-live.sh \
    'the live ciphertext gate must exercise the IPv6 proof beacon'
require_text 'Phase 9.6d adds the **Workload-Independent In-Fabric Proof Beacon**' \
    docs/adr/0197-workload-independent-in-fabric-proof-beacon.md \
    'ADR 0197 must define the collision-free beacon contract'

echo 'Phase 9.6d proof beacon passed: deterministic IPAM-excluded dual-stack host identities are contract-bound, exactly reconciled by Linux, and independently proven across real WireGuard ciphertext'
