#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

rg --fixed-strings --quiet 'kind = "EgressReachabilityPlan"' crates/unf-api/src/lib.rs
rg --fixed-strings --quiet 'kind = "EgressReachabilityObservation"' crates/unf-api/src/lib.rs
rg --fixed-strings --quiet 'status = "EgressReachabilityObservationStatus"' crates/unf-api/src/lib.rs
rg --fixed-strings --quiet 'unf-reachability-observer' deploy/kubernetes/reachability-observer-rbac.yaml
rg --fixed-strings --quiet 'EgressReachabilityEvidenceStore' crates/unf-egress/src/reachability_store.rs
rg --fixed-strings --quiet 'compile_egress_reachability_acknowledgement' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet 'reachability-evidence.json' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet 'refresh_due_egress_reachability' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet '| 8.8b | Authenticated durable reachability lifecycle | **Verified** |' docs/development/phase8-egress-fabric-plan.md
rg --fixed-strings --quiet '| Authenticated durable DQR lifecycle | **Verified** |' docs/project-status.md
rg --fixed-strings --quiet '**Status:** Accepted and implemented for Phase 8 milestone 8.8b' docs/adr/0149-authenticated-durable-dqr-lifecycle.md

cargo test -p unf-egress reachability --no-fail-fast
cargo test -p unf-api --no-fail-fast
cargo test -p unf-controller egress_api --no-fail-fast
cargo clippy -p unf-api -p unf-egress -p unf-controller --all-targets --all-features -- -D warnings
kubectl kustomize deploy >/dev/null

echo "Phase 8.8b DQR lifecycle control passed: status-only identity, durable replay, expiry, acknowledgement bridge, and safe withdrawal"
