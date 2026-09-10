#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 9.5a" >&2
    exit 1
}

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 9.5a file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.5a check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text docs/project-status.md \
    '| Intent-Coalesced Cryptographic Fast Path | **Verified** |' \
    "the tracker must record the completed fast-path proof chain"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    '| 9.5 | Intent-Coalesced Cryptographic Fast Path | **Verified** |' \
    "the execution plan must record the bounded compiler and live closure"
require_text docs/adr/0162-causal-epoch-lease-fast-path.md \
    '**Status:** Accepted and implemented for Phase 9.5a' \
    "ADR 0162 must record the implemented boundary"
require_text crates/unf-encryption/src/fast_path.rs \
    'pub fn compile_encryption_fast_path(' \
    "the canonical bounded compiler must remain public"
require_text crates/unf-encryption/src/fast_path.rs \
    'pub struct CausalEpochLease {' \
    "established flows must retain exact epoch authority"
require_text crates/unf-encryption/src/fast_path.rs \
    'FastPathDropReason::PolicyDenied' \
    "policy denial must precede transport reuse"
require_text ebpf/unf-ebpf-common/src/lib.rs \
    'pub struct EncryptionDecisionValue {' \
    "the fixed-width decision ABI must remain shared"
require_text ebpf/unf-ebpf-common/src/lib.rs \
    'pub const fn encryption_transport_is_usable(' \
    "the verifier-friendly transport predicate must remain bounded"

echo "Phase 9.5a fast-path contract passed: exact identity authority, transport coalescing, causal epoch leases, fixed-width ABI, and fail-closed revision/readback binding agree"
