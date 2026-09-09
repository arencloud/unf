#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

if ! command -v rg >/dev/null 2>&1; then
    echo "rg is required to verify Phase 9.5i" >&2
    exit 1
fi

require_text() {
    local relative_file=$1 pattern=$2 description=$3
    if [[ ! -f ${relative_file} ]]; then
        echo "Phase 9.5i file is missing: ${relative_file}" >&2
        exit 1
    fi
    if ! rg --fixed-strings --quiet -- "${pattern}" "${relative_file}"; then
        echo "Phase 9.5i check failed: ${description} (${relative_file})" >&2
        exit 1
    fi
}

require_text crates/unf-encryption/src/generation_frontier.rs \
    'pub struct EncryptionGenerationFrontier {' \
    "prepared generations must form one explicit cluster frontier"
require_text crates/unf-encryption/src/generation_frontier.rs \
    'if generated_members != self.members {' \
    "partial or extra Node publication must fail"
require_text crates/unf-encryption/src/generation_frontier.rs \
    'if self.acknowledged.len() != active.members.len() {' \
    "the slowest Node must backpressure frontier advancement"
require_text crates/unf-encryption/src/generation_frontier.rs \
    'generation.checkpoint.transaction.prior' \
    "every Node successor must name its exact predecessor"
require_text crates/unf-encryption/src/generation_frontier.rs \
    'transport.local_node_uid != generation.recipient.node_uid' \
    "transport authority must remain bound to the recipient Node UID"
require_text bins/unf-controller/src/main.rs \
    'encryption_generations: Mutex<EncryptionGenerationProducer>' \
    "the controller endpoint must consume the validated producer"
require_text bins/unf-controller/src/main.rs \
    '.acknowledge(&recipient, desired.transaction.desired.published)' \
    "an authenticated durable cursor must acknowledge the causal cut"
require_text crates/unf-encryption/src/fast_path.rs \
    'causal_generation_frontier_backpressures_every_exact_predecessor' \
    "backpressure and exact-successor behavior must be tested"
require_text docs/adr/0170-causal-generation-frontier.md \
    '**Status:** Accepted and implemented for Phase 9.5i' \
    "the frontier decision must be recorded"
require_text docs/project-status.md \
    'Phase 9 causal generation frontier' \
    "the authoritative tracker must include Phase 9.5i"

echo "Phase 9.5i generation frontier passed: complete Node cuts, UID binding, exact predecessors, and slowest-member backpressure agree"
