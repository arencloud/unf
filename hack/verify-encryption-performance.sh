#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
evidence="${project_root}/docs/benchmarks/phase9-encryption-performance.json"
expected_revision=f2a39673f34b645abdb58132183523a41d17ddac
expected_sha256=a29a3f383e4d6e871ea30d5a637212be80a27119450cc84f59039c7b905348fc

for command in jq sha256sum; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "${command} is required for the committed performance gate" >&2
        exit 1
    }
done
[[ -f ${evidence} ]] || {
    echo 'Phase 9.7h check failed: committed performance evidence is absent' >&2
    exit 1
}
actual_sha256=$(sha256sum "${evidence}" | cut -d' ' -f1)
[[ ${actual_sha256} == "${expected_sha256}" ]] || {
    echo "Phase 9.7h check failed: evidence digest ${actual_sha256} differs from ${expected_sha256}" >&2
    exit 1
}

jq -e --arg revision "${expected_revision}" '
    .schemaVersion == 1 and .revision == $revision and
    .environment.durationSeconds == 3 and
    .native.ipv4.latency.lossPercent == 0 and
    .native.ipv6.latency.lossPercent == 0 and
    .encrypted.ipv4.latency.lossPercent == 0 and
    .encrypted.ipv6.latency.lossPercent == 0 and
    .native.ipv4.throughput.throughputBitsPerSecond > 0 and
    .native.ipv6.throughput.throughputBitsPerSecond > 0 and
    .encrypted.ipv4.throughput.throughputBitsPerSecond > 0 and
    .encrypted.ipv6.throughput.throughputBitsPerSecond > 0 and
    .encrypted.capture.ciphertextPackets > 0 and
    .encrypted.capture.plaintextInnerPackets == 0 and
    .encrypted.handshakeConvergenceMs > 0 and
    .rotation.samples == 400 and
    .rotation.lostSamples >= 0 and
    (.peerScale | map(.peers)) == [1,16,64,128] and
    .mapActivity.newDirectFlow == {lookups:4,writes:1} and
    .mapActivity.newAddressBoundFlow == {lookups:5,writes:1} and
    .mapActivity.establishedFlow == {lookups:3,writes:1} and
    .mapActivity.quiescentRecoveryMutations == 0 and
    .native.ipv4.mtu.accepted and .native.ipv4.mtu.rejected and
    .native.ipv6.mtu.accepted and .native.ipv6.mtu.rejected and
    .encrypted.ipv4.mtu.accepted and .encrypted.ipv4.mtu.rejected and
    .encrypted.ipv6.mtu.accepted and .encrypted.ipv6.mtu.rejected and
    (.limitations | length) >= 3
' "${evidence}" >/dev/null || {
    echo 'Phase 9.7h check failed: committed evidence is incomplete or internally inconsistent' >&2
    exit 1
}

rg --fixed-strings --quiet 'Regression-First Performance Ledger' \
    "${project_root}/docs/adr/0207-regression-first-performance-ledger.md" || {
    echo 'Phase 9.7h check failed: accepted performance decision is absent' >&2
    exit 1
}
bash -n "${project_root}/hack/measure-encryption-performance.sh"
echo "Phase 9.7h performance passed: digest ${actual_sha256} binds complete native/encrypted dual-stack, resource, map, scale, MTU, convergence, ciphertext, and rotation evidence to ${expected_revision}"
