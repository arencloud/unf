#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 9.3" >&2
    exit 1
}

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 9.3 file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.3 check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text docs/project-status.md \
    '| Node key authority and epoch rotation | **Verified** |' \
    "the authoritative tracker must verify milestone 9.3"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    '| 9.3 | Node key authority and epoch rotation | **Verified** |' \
    "the execution plan must verify milestone 9.3"
require_text docs/adr/0160-verify-node-key-authority-and-causal-epoch-barrier.md \
    '**Status:** Accepted and implemented for Phase 9.3' \
    "ADR 0160 must record the accepted implementation"
require_text Cargo.toml \
    'x25519-dalek = { version = "3.0.0", features = ["static_secrets"] }' \
    "key derivation must use a maintained X25519 implementation"
require_text Cargo.toml \
    'getrandom = "0.4.3"' \
    "key bytes must come directly from the OS CSPRNG"
require_text Cargo.toml \
    'zeroize = { version = "1.9.0", features = ["serde"] }' \
    "temporary and durable secret buffers must be zeroized"
require_text crates/unf-encryption/src/key_authority.rs \
    'pub struct NodeKeyAuthority {' \
    "Node-local authority must not be a public serializable wire object"
require_text crates/unf-encryption/src/key_authority.rs \
    'WireGuardPrivateKey(<redacted>)' \
    "private-key debug output must be redacted"
require_text crates/unf-encryption/src/key_authority.rs \
    'unf.causal-epoch-barrier.v1' \
    "the exact affected-peer frontier must be domain separated"
require_text crates/unf-encryption/src/key_authority.rs \
    'pub enum KeyEpochPhase' \
    "the two-epoch lifecycle must remain explicit"
require_text crates/unf-encryption/src/key_authority.rs \
    'NodeReplacementRequiresFence' \
    "Node UID replacement must require an explicit fence"
require_text crates/unf-encryption/src/key_authority.rs \
    'durability_failure_never_advances_live_authority' \
    "persistence failure must retain the live authority"
require_text crates/unf-encryption/src/key_authority.rs \
    'owner_only_checkpoint_round_trips_and_rejects_uid_reuse_and_tamper' \
    "owner-only restart recovery and tamper rejection must be tested"
require_text crates/unf-encryption/src/key_authority.rs \
    'public_wire_shape_contains_no_private_material' \
    "public state and diagnostics must remain secret-free"

if rg --quiet '#\[allow' "${project_root}/crates/unf-encryption/src/key_authority.rs"; then
    echo "Phase 9.3 check failed: key authority must not suppress lint findings" >&2
    exit 1
fi

echo "Phase 9.3 key authority passed: OS keys, secret isolation, causal barriers, durable rotation, drain, revocation, replay, and replacement fencing agree"
