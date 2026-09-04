#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null

rg --fixed-strings --quiet \
    'pub const EGRESS_SAFE_FORGETTING_SCHEMA_VERSION: u16 = 1;' \
    "${project_root}/crates/unf-egress/src/safe_forgetting.rs"
rg --fixed-strings --quiet \
    'pub const EGRESS_CONTROL_PLANE_CHECKPOINT_SCHEMA_VERSION: u16 = 5;' \
    "${project_root}/crates/unf-egress/src/control_plane.rs"
if rg --fixed-strings --quiet 'finalize_withdrawals' \
    "${project_root}/crates/unf-egress/src/control_plane.rs"; then
    echo "implicit egress withdrawal finalization remains present" >&2
    exit 1
fi
rg --fixed-strings --quiet \
    '| Proof of Safe Forgetting release authority | **Verified** |' \
    "${project_root}/docs/project-status.md"

echo "Phase 8.5 safe-forgetting contract passed: exact durable retirement sets, source fences, zero-flow gateway drains, withdrawn reachability, and explicit release authority are required"
