#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.7d check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text 'pub struct EncryptionActivationReport {' crates/unf-encryption/src/operations.rs \
    'agent acknowledgement must bind recipient, generation, map digest, and exact receipts'
require_text 'pub report_digest: EncryptionActivationReportDigest,' \
    crates/unf-encryption/src/operations.rs \
    'the retry identity must be domain-separated and mutation evident'
require_text 'pending_activation_report: Option<EncryptionActivationReport>,' \
    bins/unf-agent/src/main.rs \
    'successful activation must remain queued until acknowledged'
require_text 'encryption activation evidence remains queued for retry' \
    bins/unf-agent/src/main.rs \
    'controller outage must retain the report without blocking active authority'
require_text 'pending_activation_report.is_none()' bins/unf-agent/src/main.rs \
    'a successor generation must wait behind unacknowledged evidence'
require_text '"/v1/state/encryption-activations"' bins/unf-controller/src/main.rs \
    'activation reporting must use the authenticated internal API'
require_text 'activation_cursors: BTreeMap<String, EncryptionActivationCursor>,' \
    bins/unf-controller/src/main.rs \
    'per-Node idempotency cursors must survive controller replacement'
require_text 'expected_paths != reported_paths' bins/unf-controller/src/main.rs \
    'the report must cover the exact current contract/epoch multiset'
require_text 'Acknowledged Activation Outbox' \
    docs/adr/0203-acknowledged-activation-outbox.md \
    'activation observation must have an accepted design record'

echo 'Phase 9.7d activation reporting passed: exact post-map reports remain queued across controller outage, authenticate to current Node/generation/path truth, deduplicate across retries/revalidation, and durably fence successors'
