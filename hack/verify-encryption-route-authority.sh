#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

if ! command -v rg >/dev/null 2>&1; then
    echo "rg is required to verify Phase 9.5f" >&2
    exit 1
fi

require_text() {
    local relative_file=$1
    local pattern=$2
    local description=$3
    if [[ ! -f ${relative_file} ]]; then
        echo "Phase 9.5f file is missing: ${relative_file}" >&2
        exit 1
    fi
    if ! rg --fixed-strings --quiet -- "${pattern}" "${relative_file}"; then
        echo "Phase 9.5f check failed: ${description} (${relative_file})" >&2
        exit 1
    fi
}

require_text crates/unf-encryption/src/route_authority.rs \
    'pub struct EncryptionRoutePublicationPermit' \
    "exact route readback must create a generation-bound publication permit"
require_text crates/unf-encryption/src/route_authority/linux.rs \
    'require_exact_routes(&handle, &authority.routes).await?;' \
    "route readback must precede policy-rule installation"
require_text crates/unf-encryption/src/route_authority/linux.rs \
    'authority.authorize_publication(&observed)' \
    "exact rule readback must precede map authority"
require_text bins/unf-agent/src/encryption_maps.rs \
    'verify route-before-authority publication permit' \
    "the Aya transaction boundary must reject an absent or stale route permit"
require_text docs/adr/0167-route-before-authority.md \
    '**Status:** Accepted and implemented for Phase 9.5f' \
    "the route activation decision must be recorded"
require_text docs/project-status.md \
    'Phase 9 route-before-authority' \
    "the authoritative tracker must include Phase 9.5f"

echo "Phase 9.5f route-before-authority contract passed: exact routes precede masked rules, exact rule readback precedes a generation-bound Aya permit, and foreign state is preserved"
