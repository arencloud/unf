#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.2a check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.2a" >&2
    exit 1
}

require_text docs/project-status.md \
    '| Egress Behavior Contract and reference validator | **Verified** |' \
    "the authoritative tracker must verify milestone 8.2a"
require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.2a | Egress Behavior Contract and reference validator | **Verified** |' \
    "the execution plan must verify milestone 8.2a"
require_text docs/adr/0115-verify-egress-behavior-contracts.md \
    '**Status:** Accepted and implemented for Phase 8.2a' \
    "ADR 0115 must record the accepted contract"
require_text crates/unf-egress/src/contract.rs \
    'pub const EGRESS_BEHAVIOR_CONTRACT_SCHEMA_VERSION: u16 = 1;' \
    "the wire contract must be explicitly versioned"
require_text crates/unf-egress/src/contract.rs \
    'PolicyAllowBeforeSteering' \
    "policy precedence must be an admitted invariant"
require_text crates/unf-egress/src/contract.rs \
    'pub fn verify(' \
    "agents must have an independent replay boundary"
require_text crates/unf-egress/src/contract.rs \
    'unf.egress-behavior-contract.v1' \
    "contract hashes must be domain separated"
require_text crates/unf-egress/src/contract.rs \
    'pub fn decision_witness(' \
    "bounded provenance witnesses must be derived"
require_text crates/unf-egress/src/contract.rs \
    'pub truncated: bool' \
    "failure-envelope truncation must be explicit"

echo "Phase 8.2a egress contract passed: replay, policy, allocation, gateways, capabilities, revisions, witnesses, and failures agree"
