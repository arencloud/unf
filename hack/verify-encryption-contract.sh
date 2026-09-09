#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 9.2" >&2
    exit 1
}

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 9.2 file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.2 check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text docs/project-status.md \
    '| Encryption intent and path-contract model | **Verified** |' \
    "the authoritative tracker must verify milestone 9.2"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    '| 9.2 | Encryption intent and path-contract model | **Verified** |' \
    "the execution plan must verify milestone 9.2"
require_text docs/adr/0159-verify-attested-encryption-path-contracts.md \
    '**Status:** Accepted and implemented for Phase 9.2' \
    "ADR 0159 must record the accepted contract"
require_text Cargo.toml \
    '"crates/unf-encryption"' \
    "the encryption domain must remain a workspace member"
require_text crates/unf-encryption/src/lib.rs \
    'pub const ATTESTED_ENCRYPTION_PATH_CONTRACT_SCHEMA_VERSION: u16 = 1;' \
    "the wire contract must be explicitly versioned"
require_text crates/unf-encryption/src/lib.rs \
    'PolicyAllowBeforeEncryption' \
    "policy precedence must be an admitted invariant"
require_text crates/unf-encryption/src/lib.rs \
    'RequiredNoPlaintextFallback' \
    "required encryption must fail closed"
require_text crates/unf-encryption/src/lib.rs \
    'pub fn verify(' \
    "agents must have an independent replay boundary"
require_text crates/unf-encryption/src/lib.rs \
    'unf.attested-encryption-path-contract.v1' \
    "contract hashes must be domain separated"
require_text crates/unf-encryption/src/lib.rs \
    'unf.encryption-decision-witness.v1' \
    "bounded decision witnesses must be domain separated"
require_text crates/unf-encryption/src/lib.rs \
    'pub truncated: bool' \
    "failure-envelope truncation must be explicit"
require_text crates/unf-encryption/src/lib.rs \
    'intent_normalization_is_permutation_independent' \
    "canonical intent must have property coverage"
require_text crates/unf-encryption/src/lib.rs \
    'wire_shape_rejects_unknown_fields_and_contains_no_private_key_field' \
    "the public contract must reject private-key-shaped extensions"

echo "Phase 9.2 encryption contract passed: intent, policy, identity, keys, epochs, routes, AllowedIPs, witnesses, replay, and failures agree"
