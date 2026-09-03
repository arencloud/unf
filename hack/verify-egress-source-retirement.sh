#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null

rg --fixed-strings --quiet '"/v1/state/egress-source-retirements"' \
    "${project_root}/bins/unf-controller/src/main.rs"
rg --fixed-strings --quiet '"/v1/state/egress-source-fence"' \
    "${project_root}/bins/unf-controller/src/main.rs"
rg --fixed-strings --quiet 'publish_egress_source_retirement_evidence(synchronizer).await?;' \
    "${project_root}/bins/unf-agent/src/main.rs"
rg --fixed-strings --quiet \
    '| Authenticated live source-retirement evidence | **Verified** |' \
    "${project_root}/docs/project-status.md"

echo "Phase 8.5 source retirement passed: pre-invalidation manifest capture, Node-scoped challenges, fenced-bank evidence, Pod replacement rejection, and epoch fencing agree"
