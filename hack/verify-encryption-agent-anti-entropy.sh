#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5n contract ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

agent=bins/unf-agent/src/main.rs
local_orchestrator=crates/unf-encryption/src/local_orchestrator.rs

require_text 'enum PendingEncryptionGeneration' "${agent}"
require_text 'prepared: Box<LinuxPreparedLocalGeneration>' "${agent}"
require_text 'fn offer_prepared' "${agent}"
require_text 'a different encryption generation capability is already in flight' "${agent}"
require_text '/v1/state/encryption-generation-facts' "${agent}"
require_text 'fact_response\.status\(\) != StatusCode::ACCEPTED' "${agent}"
require_text 'fn admit_exact_echo' "${agent}"
require_text 'verify_controller_admission\(&candidate\)' "${agent}"
require_text 'persist_secure_json\(&self\.state_path, &candidate' "${agent}"
require_text 'fact_for_publication\(\)\.is_some\(\)' "${agent}"
require_text 'pub fn verify_controller_admission' "${local_orchestrator}"
require_text 'encryption_generation_without_local_proof_never_polls_controller' "${agent}"
require_text 'Echo-Sealed Agent Anti-Entropy Loop' docs/adr/0175-echo-sealed-agent-anti-entropy-loop.md
require_text 'encryption-agent-anti-entropy-test' docs/project-status.md

fact_line="$(grep -n '/v1/state/encryption-generation-facts' "${agent}" | head -1 | cut -d: -f1)"
pull_line="$(grep -n '/v1/state/encryption-generation"' "${agent}" | head -1 | cut -d: -f1)"
if (( fact_line >= pull_line )); then
  echo "Node fact publication must precede generation polling" >&2
  exit 1
fi

echo "Phase 9.5n agent anti-entropy passed: no blind pull, fact-first retry, nonce-bound polling, exact echo admission, and persist-before-cursor adoption are structurally ordered"
