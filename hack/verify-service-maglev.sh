#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
report=$(mktemp)
trap 'rm -f "${report}"' EXIT

command -v jq >/dev/null 2>&1 || {
    echo "jq is required to verify the Maglev measurement" >&2
    exit 1
}

cd "${project_root}"
cargo run --quiet -p unf-service --example maglev-measurement --release >"${report}"

jq -e '
    .schemaVersion == 1 and
    .fixture.flowCount == 200000 and
    .fixture.backendCardinalities == [2,8,32,128,512,1024,2048,4096] and
    .fixture.slotBytes == 32 and
    .acceptance.selectedMinSlotsPerBackend == 16 and
    .acceptance.maximumTableSize == 65537 and
    .acceptance.packetMapLookupsStableHash == 1 and
    .acceptance.packetMapLookupsMaglev == 1 and
    (.results | length) == 8 and
    all(.results[];
        .tableSize >= (.backendCount * 16) and
        .tableSize <= 65537 and
        .maglevMemoryBytes == (.tableSize * 32) and
        .stableHashMemoryBytes == (.backendCount * 32) and
        .maglevUpdateMapWrites == .tableSize and
        .stableHashUpdateMapWrites == .backendCount and
        .maglevTableDistributionErrorPpm <= 62500 and
        .stableHashCompileNs > 0 and
        .maglevCompileNs > 0 and
        .stableHashLookupNs > 0 and
        .maglevLookupNs > 0 and
        ((.maglevAddRemapPpm == null and .stableHashAddRemapPpm == null) or
         (.maglevAddRemapPpm < .stableHashAddRemapPpm)))
' "${report}" >/dev/null

echo "Phase 7 Maglev measurement passed: deterministic balance, add disruption, memory, compile/update cost, and one-map packet lookup are bounded"
