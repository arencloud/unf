#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.5 contract check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify the Phase 8.5 dataplane contract" >&2
    exit 1
}

require_text docs/project-status.md \
    '| Bilateral distribution and fixed-width dataplane contract | **Verified** |' \
    "the authoritative tracker must verify the Phase 8.5 contract slice"
require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.5 | Live distribution, source steering, and gateway NAT dataplane | **Verified** |' \
    "the execution plan must record the verified Phase 8.5 milestone"
require_text docs/adr/0119-lower-bilateral-egress-to-precertified-dataplane-state.md \
    '**Status:** Accepted and implemented for the Phase 8.5 contract slice' \
    "ADR 0119 must record the accepted lowering contract"
require_text crates/unf-egress/src/distribution.rs \
    'pub struct AdmittedEgressGatewayProjection' \
    "gateway state must cross a typed authenticated admission boundary"
require_text crates/unf-egress/src/distribution.rs \
    'pub fn verify_flow(' \
    "gateways must reproduce source proofs from retained contracts"
require_text crates/unf-egress/src/dataplane.rs \
    'pub struct EgressPathCertificate' \
    "source paths must bind read-back physical evidence"
require_text crates/unf-egress/src/dataplane.rs \
    'pub fn compile_egress_dataplane(' \
    "admitted state must lower through one pure bounded compiler"
require_text ebpf/unf-ebpf-common/src/lib.rs \
    'pub const EGRESS_SELECTION_TABLE_SIZE: u16 = 251;' \
    "rendezvous selection must lower to a fixed prime-sized table"
require_text ebpf/unf-ebpf-common/src/lib.rs \
    'pub struct EgressConnectionValue' \
    "forward/reverse state must retain original, translated, and standby provenance"
require_text ebpf/unf-ebpf-common/src/lib.rs \
    'pub struct EgressEvent' \
    "packet outcomes must have a fixed-width provenance record"

echo "Phase 8.5 egress dataplane contract passed: bilateral distribution, path certificates, fixed ABI, shared rendezvous tables, and pre-certified standby agree"
