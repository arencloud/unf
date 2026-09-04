#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

rg --fixed-strings --quiet 'kind = "EgressInternetClassification"' crates/unf-api/src/lib.rs
rg --fixed-strings --quiet 'unf-internet-classifier-publisher' deploy/kubernetes/internet-classifier-rbac.yaml
rg --fixed-strings --quiet 'EgressInternetClassificationStore' crates/unf-egress/src/internet_store.rs
rg --fixed-strings --quiet 'persist_egress_desired_state(state).await' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet 'internet-classifications.json' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet 'watch_egress_internet_classifications' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet '| 8.7f | Authenticated durable classifier lifecycle | **Verified** |' docs/development/phase8-egress-fabric-plan.md
rg --fixed-strings --quiet '| Authenticated durable internet-classifier lifecycle | **Verified** |' docs/project-status.md
rg --fixed-strings --quiet '**Status:** Accepted and implemented for Phase 8 milestone 8.7f' docs/adr/0147-authenticated-durable-internet-classifier-lifecycle.md

cargo test -p unf-egress internet_store --no-fail-fast
cargo test -p unf-api --no-fail-fast
cargo test -p unf-controller egress_api --no-fail-fast
cargo clippy -p unf-api -p unf-egress -p unf-controller --all-targets --all-features -- -D warnings

echo "Phase 8.7f classifier lifecycle control passed: Kubernetes-authenticated, replay-checked, durable-before-distribution, and restart-safe"
