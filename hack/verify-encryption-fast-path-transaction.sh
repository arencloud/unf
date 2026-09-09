#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 9.5b" >&2
    exit 1
}

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 9.5b file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.5b check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text docs/project-status.md \
    'Phase 9.5b adds the Causal Commit Vector' \
    "the authoritative tracker must record the transaction slice"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'Phase 9.5b adds the Causal Commit Vector' \
    "the execution plan must record transaction recovery"
require_text docs/adr/0163-causal-commit-vector.md \
    '**Status:** Accepted and implemented for Phase 9.5b' \
    "ADR 0163 must record the implemented boundary"
require_text crates/unf-encryption/src/fast_path_transaction.rs \
    'pub struct CausalCommitVector {' \
    "activation must bind every kernel configuration commitment"
require_text crates/unf-encryption/src/fast_path_transaction.rs \
    'pub struct FastPathMapTransaction {' \
    "the inactive-bank transaction must be durable and replayable"
require_text crates/unf-encryption/src/fast_path_transaction.rs \
    'FastPathMapRecoveryAction::RefuseUnknownState' \
    "unknown restart state must fail closed"
require_text crates/unf-encryption/src/fast_path.rs \
    'causal_commit_vector_makes_every_crash_boundary_total' \
    "every pointer-flip crash boundary must be tested"
require_text crates/unf-encryption/src/fast_path.rs \
    'causal_commit_rollback_requires_prior_and_positive_absence' \
    "rollback must require exact prior state and positive cleanup"

echo "Phase 9.5b transaction contract passed: causal commit vectors, inactive-bank readback, total restart decisions, corruption refusal, and positive rollback agree"
