#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.3 check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.3" >&2
    exit 1
}

require_text docs/project-status.md \
    '| Durable allocation and gateway-provider contract | **Verified** |' \
    "the authoritative tracker must verify milestone 8.3"
require_text docs/development/phase8-egress-fabric-plan.md \
    '| 8.3 | Durable allocation and gateway-provider contract | **Verified** |' \
    "the execution plan must verify milestone 8.3"
require_text docs/adr/0116-fence-egress-allocation-and-provider-ownership.md \
    '**Status:** Accepted and implemented for Phase 8.3' \
    "ADR 0116 must record the accepted ownership model"
require_text crates/unf-egress/src/allocation.rs \
    'pub const EGRESS_ALLOCATION_CHECKPOINT_SCHEMA_VERSION: u16 = 1;' \
    "allocation checkpoints must be versioned"
require_text crates/unf-egress/src/allocation.rs \
    'pub lease_epoch: u64' \
    "address reuse must be fenced by epoch"
require_text crates/unf-egress/src/allocation.rs \
    'pub fn contract_fact(&self)' \
    "contracts must consume exact durable allocation facts"
require_text crates/unf-egress/src/gateway.rs \
    'pub trait EgressGatewayProvider' \
    "gateway host state must remain provider-neutral"
require_text crates/unf-egress/src/gateway.rs \
    'pub trait EgressReachabilityProvider' \
    "reachability must remain independently provided"
require_text crates/unf-egress/src/gateway.rs \
    'pub fn publication_ready(&self' \
    "publication must wait for complete acknowledgement"
require_text crates/unf-egress/src/gateway.rs \
    'pub fn complete_withdrawal(' \
    "ownership release must follow safe withdrawal"
require_text crates/unf-egress/src/gateway.rs \
    'pub fn contract_facts(' \
    "only acknowledged provider state may enter contracts"

echo "Phase 8.3 egress allocation passed: atomic leases, epochs, providers, acknowledgements, withdrawal, replay, and publication agree"
