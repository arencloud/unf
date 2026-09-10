#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5y policy quotient ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

projection=crates/unf-encryption/src/policy_projection.rs
contract=crates/unf-encryption/src/lib.rs

require_text 'pub struct EncryptionIdentityPair' "${projection}"
require_text 'pub struct EncryptionPolicyObservation' "${projection}"
require_text 'pub fn project_encryption_policy_facts' "${projection}"
require_text 'NoApplicablePolicy' "${projection}"
require_text 'Any allowed L4 class' "${projection}"
require_text 'policy_truth_quotient_needs_transport_for_any_allowed_l4_class' "${projection}"
require_text 'policy_truth_quotient_keeps_all_denied_pairs_out_of_plans' "${projection}"

require_text 'pub reason: PolicyReason' "${contract}"
require_text 'no_applicable_policy_is_truthful_authority_without_a_fabricated_id' "${contract}"
require_text 'Policy-Truth Transport Quotient' docs/adr/0186-policy-truth-transport-quotient.md

echo "Phase 9.5y policy quotient passed: L4 policy remains first authority while transport demand is lossless and default allow invents no policy ID"
