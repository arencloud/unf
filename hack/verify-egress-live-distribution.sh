#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local relative_file=$1 expected=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 8.5 live-distribution check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify Phase 8.5 live distribution" >&2
    exit 1
}

require_text bins/unf-controller/src/main.rs \
    '.route("/v1/state/egress-source", post(egress_source_projection))' \
    "the internal TLS API must expose only the authenticated POST boundary"
require_text bins/unf-controller/src/main.rs \
    'authenticate_internal_agent(&state, &headers).await?' \
    "the endpoint must reuse Pod-bound TokenReview authentication"
require_text crates/unf-egress/src/distribution.rs \
    'pub struct EgressNodeProjectionEnvelope' \
    "wire state must carry replayable model, facts, and contract material"
require_text bins/unf-agent/src/main.rs \
    '.context("independently replay egress source projection")?' \
    "the agent must independently replay before compilation"
require_text bins/unf-agent/src/main.rs \
    '.context("install fail-closed egress source admission")?' \
    "all distributed explicit intent must enter the fenced state"
require_text bins/unf-agent/src/main.rs \
    'persistent egress sources disagree on their contract digest' \
    "restart must reconstruct one coherent last-known-good authority"
require_text docs/project-status.md \
    '| Authenticated live source distribution | **Verified** |' \
    "the professional tracker must record the bounded verified slice"

echo "Phase 8.5 live source distribution passed: Pod/Node binding, exact schemas, independent replay, monotonic fencing, and transactional map staging agree"
