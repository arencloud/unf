#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

if ! command -v rg >/dev/null 2>&1; then
    echo "rg is required to verify Phase 9.5e" >&2
    exit 1
fi

require_text() {
    local relative_file=$1
    local pattern=$2
    local description=$3
    if [[ ! -f ${relative_file} ]]; then
        echo "Phase 9.5e file is missing: ${relative_file}" >&2
        exit 1
    fi
    if ! rg --fixed-strings --quiet -- "${pattern}" "${relative_file}"; then
        echo "Phase 9.5e check failed: ${description} (${relative_file})" >&2
        exit 1
    fi
}

require_text ebpf/unf-ebpf-common/src/lib.rs \
    'pub const ENCRYPTION_ROUTE_MARK_MASK: u32 = 0x00ff_ff00;' \
    "encryption must own only its documented mark field"
require_text ebpf/unf-ebpf-common/src/lib.rs \
    'pub const fn encryption_route_mark(outer_fwmark: u32) -> Option<u32>' \
    "outer and inner route classes must be distinct by construction"
require_text ebpf/unf-ebpf-common/src/lib.rs \
    'pub const fn apply_encryption_route_mark(existing: u32, route_mark: u32) -> Option<u32>' \
    "route selection must preserve neighboring mark ownership"
require_text crates/unf-encryption/src/fast_path.rs \
    'RouteMarkCollision' \
    "one selector cannot authorize conflicting route tables"
require_text crates/unf-encryption/src/fast_path.rs \
    'route_mark_mask: ENCRYPTION_ROUTE_MARK_MASK' \
    "packet decisions must carry the exact mark lease"
require_text bins/unf-agent/src/encryption_maps.rs \
    'encryption_route_mark(fwmark).is_none()' \
    "persistent map recovery must reject incompatible outer marks"
require_text docs/adr/0166-cooperative-route-mark-lease.md \
    '**Status:** Accepted and implemented for Phase 9.5e' \
    "the route-mark decision must be recorded"
require_text docs/project-status.md \
    'Phase 9 cooperative route-mark lease' \
    "the authoritative tracker must include Phase 9.5e"

echo "Phase 9.5e route-mark contract passed: inner/outer separation, exhaustive collision proof, neighboring ownership, exact release, and route-table authority agree"
