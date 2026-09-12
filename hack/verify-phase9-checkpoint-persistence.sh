#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture='{"stage":"required","controllerPod":"controller-fixture","writes":1,"errors":0,"controllerRestarts":0,"controllerMemoryLimit":"2Gi","storedBytes":500,"descriptor":{"schemaVersion":1,"codec":"gzip","compressedBytes":100,"uncompressedBytes":1000}}'
valid() {
    jq -L "${root}/hack" -e 'include "phase9-qualification"; phase9_checkpoint_persistence_valid' >/dev/null
}
valid <<<"${fixture}"
jq '.descriptor.schemaVersion = 2 | .descriptor.codec = "zstd"' <<<"${fixture}" | valid
for mutation in \
    '.errors = 1' '.errors = null' '.writes = 0' '.writes = -1' '.writes = 1.5' \
    '.controllerRestarts = 1' '.controllerMemoryLimit = "8Gi"' \
    '.descriptor.schemaVersion = 2' '.descriptor.codec = "zstd"' \
    '.descriptor.schemaVersion = 3' '.descriptor.codec = "unknown"' \
    '.descriptor.uncompressedBytes = 64000001' '.descriptor.uncompressedBytes = null' \
    '.storedBytes = 900001' '.storedBytes = 0' '.storedBytes = 100' \
    '.controllerPod = ""' '.stage = ""'; do
    if jq "${mutation}" <<<"${fixture}" | valid; then
        echo "checkpoint persistence gate accepted invalid evidence: ${mutation}" >&2
        exit 1
    fi
done
echo "Phase 9 checkpoint persistence evidence rejects errors, restarts, unsupported codecs and oversized state"
