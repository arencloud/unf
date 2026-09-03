#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null

rg --fixed-strings --quiet '"/v1/state/egress-gateway-retirements"' \
    "${project_root}/bins/unf-controller/src/main.rs"
rg --fixed-strings --quiet '"/v1/state/egress-gateway-drain"' \
    "${project_root}/bins/unf-controller/src/main.rs"
rg --fixed-strings --quiet 'ClockId::Boottime' \
    "${project_root}/bins/unf-agent/src/main.rs"
rg --fixed-strings --quiet 'plan.intent != manifest.owner' \
    "${project_root}/bins/unf-agent/src/main.rs"
rg --fixed-strings --quiet \
    '| Authenticated lease-specific gateway retirement | **Verified** |' \
    "${project_root}/docs/project-status.md"

echo "Phase 8.5 gateway retirement passed: lease-scoped projection exclusion, pair-safe natural expiry, BOOTTIME rescan, Node/Pod/epoch authentication, and applied-state verification agree"
