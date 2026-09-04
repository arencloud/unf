#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

rg --fixed-strings --quiet 'diversity-quorum-reachability-v1' crates/unf-egress/src/reachability.rs
rg --fixed-strings --quiet 'minimum_failure_domains' crates/unf-egress/src/reachability.rs
rg --fixed-strings --quiet 'authority_until_unix_seconds' crates/unf-egress/src/reachability.rs
rg --fixed-strings --quiet 'egress_reachability_verdict_at' crates/unf-egress/src/reachability.rs
rg --fixed-strings --quiet 'EgressReachabilityVerdict::DenyClosed' crates/unf-egress/src/reachability.rs
rg --fixed-strings --quiet '| 8.8a | Diversity-Quorum Reachability contract | **Verified** |' docs/development/phase8-egress-fabric-plan.md
rg --fixed-strings --quiet '| Diversity-Quorum Reachability contract | **Verified** |' docs/project-status.md
rg --fixed-strings --quiet '**Status:** Accepted and implemented for Phase 8 milestone 8.8a' docs/adr/0148-diversity-quorum-egress-reachability.md

cargo test -p unf-egress reachability::tests --no-fail-fast
cargo clippy -p unf-egress --all-targets --all-features -- -D warnings

echo "Phase 8.8a reachability contract passed: lease-bound, diversity-aware, finite, exact-path, dual-stack, and fail-closed"
