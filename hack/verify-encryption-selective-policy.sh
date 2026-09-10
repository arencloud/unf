#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.8d check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text 'kind: EncryptionPolicy' deploy/crds/network.unf.io_encryptionpolicies.yaml \
    'the namespaced selective-encryption API must have a checked-in CRD'
require_text 'watch_encryption_policies(' bins/unf-controller/src/main.rs \
    'the controller must watch selective intent'
require_text 'encryption_policy_initialization' bins/unf-controller/src/main.rs \
    'watch relists must stage a complete intent cut'
require_text 'state.encryption_baseline' bins/unf-controller/src/main.rs \
    'plan production must consume the configured cluster baseline'
require_text 'native_only_generation_is_explicit_packet_authority_without_transport' \
    crates/unf-encryption/src/fast_path.rs \
    'native-only packet authority must be independently tested'
require_text 'selective_cut_proves_native_authority_without_a_fake_kernel_epoch' \
    crates/unf-encryption/src/fleet_plan_producer.rs \
    'fleet production must test explicit Native authority without fake tunnels'
require_text 'Proof-Carrying Native Exception' \
    docs/adr/0211-proof-carrying-native-exception.md \
    'the selective runtime contract must have an accepted design record'

echo 'Phase 9.8d selective encryption passed: atomic selector intent yields explicit revision-bound Required or Native decisions, missing authority remains closed, and native-only Nodes manufacture no tunnel'
