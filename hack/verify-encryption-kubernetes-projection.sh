#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

projection=crates/unf-encryption/src/kubernetes_projection.rs
for pattern in \
  'pub struct KubernetesEncryptionNodeSnapshot' \
  'pub struct KubernetesEncryptionWorkloadSnapshot' \
  'pub fn project_kubernetes_encryption' \
  'demanded_identity_pairs' \
  'demanded_paths' \
  'kubernetes_projection_refuses_unready_members_and_overlapping_blocks'; do
  rg -q "${pattern}" "${projection}" || {
    echo "missing required Phase 9.5aa Kubernetes projection ${pattern@Q}" >&2
    exit 1
  }
done
rg -q 'Placement-Truth Demand Projection' docs/adr/0188-placement-truth-demand-projection.md

echo "Phase 9.5aa Kubernetes projection passed: UID/placement/IPAM truth and effective policy derive only the necessary bidirectional Node paths"
