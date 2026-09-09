#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5k contract ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

require_text 'GENERATION_FACT_DIGEST_DOMAIN' crates/unf-encryption/src/generation_reconciler.rs
require_text 'replace_membership' crates/unf-encryption/src/generation_reconciler.rs
require_text 'self\.facts\.clear\(\)' crates/unf-encryption/src/generation_reconciler.rs
require_text 'Equivocation' crates/unf-encryption/src/generation_reconciler.rs
require_text 'revisions\.any' crates/unf-encryption/src/generation_reconciler.rs
require_text 'encryption-generation-facts' bins/unf-controller/src/main.rs
require_text 'agent_application_is_current' bins/unf-controller/src/main.rs
require_text 'encryption_generation_membership' bins/unf-controller/src/main.rs
require_text 'encryption_generation_frontiers_published' bins/unf-controller/src/main.rs
require_text 'complete_cut_fact_reconciler_never_mixes_membership_truth' crates/unf-encryption/src/fast_path.rs
require_text 'Complete-Cut Fact Reconciler' docs/adr/0172-complete-cut-fact-reconciler.md
require_text 'encryption-generation-reconciler-test' docs/project-status.md

kubectl kustomize deploy/kubernetes >/dev/null
kubectl kustomize deploy/openshift >/dev/null
kubectl kustomize deploy/openshift-primary-cni/runtime >/dev/null

echo "Phase 9.5k generation reconciler passed: authenticated Node-local facts publish only as one exact Kubernetes membership cut"
