#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5u transparency ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

ledger=crates/unf-encryption/src/key_transparency.rs

require_text 'pub struct NodeKeyTransparencyCut' "${ledger}"
require_text 'members: Vec<EncryptionGenerationRecipient>' "${ledger}"
require_text 'publications: Vec<NodeKeyPublication>' "${ledger}"
require_text 'epoch\.topology_revision != self\.membership_revision' "${ledger}"
require_text 'pub struct NodeKeyTransparencyLedger' "${ledger}"
require_text 'pub fn replace_membership' "${ledger}"
require_text 'self\.publications\.clear\(\)' "${ledger}"
require_text 'admit_authenticated_publication' "${ledger}"
require_text 'pub fn complete_cut' "${ledger}"
require_text 'public_key_transparency_requires_the_complete_exact_membership_cut' \
  crates/unf-encryption/src/key_authority.rs
require_text 'Node-Local Public-Key Transparency Cut' \
  docs/adr/0182-node-local-public-key-transparency-cut.md

if grep -Eq 'private_key|privateKey' "${ledger}"; then
  echo "key transparency must never contain private-key material" >&2
  exit 1
fi

if ! grep -B 2 'pub struct NodeKeyTransparencyCut {' "${ledger}" \
  | grep -q 'deny_unknown_fields'; then
  echo "key transparency cuts must reject unknown fields" >&2
  exit 1
fi

echo "Phase 9.5u key transparency passed: public-only Node publications join only as one exact authenticated membership cut"
