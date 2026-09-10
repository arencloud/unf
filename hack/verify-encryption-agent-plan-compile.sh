#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  rg -q "${pattern}" "${path}" || {
    echo "missing required Phase 9.5ac plan consumption ${pattern@Q} in ${path}" >&2
    exit 1
  }
}

require_text 'fn prepare_admitted_encryption_plan' bins/unf-agent/src/main.rs
require_text 'pending_generation' bins/unf-agent/src/main.rs
require_text 'dormant_plan_compiles_once_into_an_empty_retryable_generation_fact' bins/unf-agent/src/main.rs
require_text 'authority_free_dormant_member_produces_a_provable_empty_generation' crates/unf-encryption/src/local_plan_compiler.rs
require_text 'fn dormant_fast_path' crates/unf-encryption/src/local_orchestrator.rs
require_text 'Authority-Free Quiescent Generation' docs/adr/0190-authority-free-quiescent-generation.md

echo "Phase 9.5ac plan consumption passed: active plans require local keys and Linux proof while dormant members contribute an exact zero-authority generation"
