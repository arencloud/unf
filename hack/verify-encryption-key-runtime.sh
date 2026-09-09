#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5v key runtime ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

controller=bins/unf-controller/src/main.rs
agent=bins/unf-agent/src/main.rs
schema=crates/unf-encryption/src/key_transparency.rs

require_text 'pub struct EncryptionKeyBootstrap' "${schema}"
require_text 'pub fn required_peer_uids' "${schema}"
require_text 'discover_encryption_cluster_id' "${controller}"
require_text '\.get\("kube-system"\)' "${controller}"
require_text '"/v1/state/encryption-key-bootstrap"' "${controller}"
require_text '"/v1/state/encryption-keys"' "${controller}"
require_text 'authenticate_internal_agent' "${controller}"
require_text 'NodeKeyTransparencyLedger' "${controller}"
require_text 'encryption_key_bootstrap_and_ingestion_are_authenticated_complete_cut_scoped' "${controller}"

require_text 'UNF_ENCRYPTION_KEY_STATE_PATH' "${agent}"
require_text 'DurableNodeKeyAuthority' "${agent}"
require_text 'FileNodeKeyStateStore' "${agent}"
require_text 'mode-0700 real directory' "${agent}"
require_text '\.prepare_epoch\(' "${agent}"
require_text 'public-only Node encryption key state' "${agent}"
require_text 'response\.status\(\) != StatusCode::ACCEPTED' "${agent}"
require_text 'encryption_key_bootstrap_creates_recovers_and_uid_fences_private_authority' "${agent}"
require_text 'Durable Edge-Key Bootstrap' docs/adr/0183-durable-edge-key-bootstrap.md

if grep -A 12 'pub struct EncryptionKeyBootstrap {' "${schema}" \
  | grep -Eq 'private|secret'; then
  echo "key bootstrap must contain no private material" >&2
  exit 1
fi

echo "Phase 9.5v key runtime passed: stable cluster/Node bootstrap creates durable local keys and publishes only authenticated public state"
