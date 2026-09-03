#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.4a check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.4a" >&2
    exit 1
}

require_text docs/project-status.md \
    '| Egress Proof Chain and zero-leak admission | **Verified** |' \
    "the authoritative tracker must verify milestone 8.4a"
require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.4a | Egress Proof Chain and zero-leak admission | **Verified** |' \
    "the execution plan must verify milestone 8.4a"
require_text docs/adr/0118-prove-bilateral-zero-leak-egress-decisions.md \
    '**Status:** Accepted and implemented for Phase 8.4a' \
    "ADR 0118 must record the accepted proof-chain contract"
require_text crates/unf-egress/src/proof.rs \
    'pub struct EgressAdmissionGuard' \
    "explicit intent must have an identity-indexed admission guard"
require_text crates/unf-egress/src/proof.rs \
    'pub fn fence(' \
    "explicit intent must enter a fail-closed fence before activation"
require_text crates/unf-egress/src/proof.rs \
    'pub fn verify_at_gateway(' \
    "the selected gateway must independently reproduce each proof"
require_text crates/unf-egress/src/proof.rs \
    'unf.egress-address-rendezvous.v1' \
    "multiple-address selection must be deterministic and domain separated"
require_text crates/unf-egress/src/proof.rs \
    'unf.egress-gateway-rendezvous.v1' \
    "gateway selection must be deterministic and domain separated"
require_text crates/unf-egress/src/proof.rs \
    'fragments are unsupported' \
    "unsupported fragments must fail closed"

echo "Phase 8.4a egress proof chain passed: admission fencing, deterministic selection, bilateral replay, mutation rejection, and safe withdrawal agree"
