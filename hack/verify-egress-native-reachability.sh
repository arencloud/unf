#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

rg --fixed-strings --quiet 'nonce-bound-kernel-ownership-v1' crates/unf-egress/src/native_reachability.rs
rg --fixed-strings --quiet '"/v1/egress-reachability/probe"' bins/unf-agent/src/main.rs
rg --fixed-strings --quiet 'native_reachability_owned_addresses' bins/unf-agent/src/main.rs
rg --fixed-strings --quiet 'reconcile_native_egress_reachability_plans' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet 'minimum_failure_domains: 2' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet 'network.unf.io/managed-native-reachability' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet '| 8.8c | Native live reference provider | **Verified** |' docs/development/phase8-egress-fabric-plan.md
rg --fixed-strings --quiet '| Native live reference-provider lifecycle | **Verified** |' docs/project-status.md
rg --fixed-strings --quiet '**Status:** Accepted and implemented for Phase 8 milestone 8.8c' docs/adr/0150-native-diversity-reachability.md

cargo test -p unf-egress native_reachability --no-fail-fast
cargo test -p unf-agent native_reachability --no-fail-fast
cargo test -p unf-controller native_reachability --no-fail-fast
cargo clippy -p unf-egress -p unf-agent -p unf-controller --all-targets --all-features -- -D warnings
kubectl kustomize deploy >/dev/null

echo "Phase 8.8c native reachability control passed: controller-owned plans, lease-bound kernel probes, provider receipt, diverse fabric quorum, and exact cleanup"
