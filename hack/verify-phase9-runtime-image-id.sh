#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
digest=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
fixture=$(jq -cn --arg image "quay.io/example/agent@sha256:$digest" '{image:$image,imageID:$image}')
valid() {
    jq -L "${root}/hack" -e 'include "phase9-qualification"; phase9_runtime_image_id_valid' >/dev/null
}
valid <<<"$fixture"
jq --arg digest "$digest" '.image="localhost/unf-agent:dev" | .imageID="sha256:"+$digest' <<<"$fixture" | valid
for mutation in \
    '.imageID=null' '.imageID=""' '.imageID="sha256:abc"' \
    '.imageID="sha256:not-a-digest"' '.imageID += "\n"' \
    '.imageID="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"' \
    '.image += "\n" | .imageID=.image' \
    '.image="quay.io/example/agent:latest"' \
    '.image="quay.io/foreign/agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"' \
    '.imageID |= sub("0123456789abcdef";"1123456789abcdef")' \
    '.imageID="containerd://unknown"' '.image=null'; do
    if jq "$mutation" <<<"$fixture" | valid; then
        echo "runtime image check accepted invalid identity: $mutation" >&2
        exit 1
    fi
done
echo "Phase 9 runtime identity accepts exact qualified references and rejects malformed/mismatched IDs"
