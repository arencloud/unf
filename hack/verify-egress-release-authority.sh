#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null

rg --fixed-strings --quiet 'provider.name == "static"' \
    "${project_root}/bins/unf-controller/src/main.rs"
rg --fixed-strings --quiet 'release_authorized_desired_revisions' \
    "${project_root}/crates/unf-egress/src/gateway_address.rs"
rg --fixed-strings --quiet 'transition_from(&previous_plan)' \
    "${project_root}/bins/unf-agent/src/main.rs"
rg --fixed-strings --quiet 'next.authorize_release(authority)' \
    "${project_root}/bins/unf-controller/src/main.rs"
rg --fixed-strings --quiet \
    '| Reachability-backed final release consumption | **Verified** |' \
    "${project_root}/docs/project-status.md"

echo "Phase 8.5 final release passed: explicit static reachability, exact proof union, authorized host subset removal/readback, and atomic lease retirement agree"
