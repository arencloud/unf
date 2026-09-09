#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5w key attestation ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

schema=crates/unf-encryption/src/key_attestation.rs
controller=bins/unf-controller/src/main.rs
agent=bins/unf-agent/src/main.rs

require_text 'pub struct NodeKeyAttestationRound' "${schema}"
require_text 'pub struct NodeKeyAttestationRow' "${schema}"
require_text 'pub struct NodeKeyAttestationCut' "${schema}"
require_text 'complete N.\(N-1\) matrix' "${schema}"
require_text 'begin_if_needed' "${schema}"
require_text 'observe_row' "${schema}"
require_text 'complete_cut_for' "${schema}"
require_text 'reciprocal_witness_matrix_releases_only_complete_columns' "${schema}"

require_text '"/v1/state/encryption-key-attestation-round"' "${controller}"
require_text '"/v1/state/encryption-key-attestation-rows"' "${controller}"
require_text '"/v1/state/encryption-key-attestation-cut"' "${controller}"
require_text 'authenticate_internal_agent' "${controller}"
require_text 'encryption_key_attestation_releases_only_an_authenticated_complete_matrix' "${controller}"

require_text 'bind_attestation_cut' "${agent}"
require_text 'durably record reciprocal peer key acknowledgement' "${agent}"
require_text 'publish_node_key_state' "${agent}"
require_text 'reciprocal_key_attestation_is_durable_and_complete_cut_only' "${agent}"
require_text 'Reciprocal Witness Matrix' docs/adr/0184-reciprocal-key-witness-matrix.md

if grep -Eq 'WireGuardPrivateKey|private_key_for_kernel|expose_for_kernel' "${schema}"; then
  echo "reciprocal witness protocol must contain no private key authority" >&2
  exit 1
fi

echo "Phase 9.5w key attestation passed: authenticated restart-stable rows release durable readiness only as a complete fleet matrix"
