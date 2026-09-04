#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

rg --fixed-strings --quiet 'pub discovery_names: Vec<String>' crates/unf-egress/src/fqdn.rs
rg --fixed-strings --quiet 'pub resolver_addresses: Vec<IpAddr>' crates/unf-egress/src/fqdn.rs
rg --fixed-strings --quiet 'wrong_resolver_observations' crates/unf-egress/src/fqdn.rs
rg --fixed-strings --quiet 'unauthorized_name_observations' crates/unf-egress/src/fqdn.rs
rg --fixed-strings --quiet 'FQDN view observation target set exceeds its atomic batch bound' bins/unf-agent/src/main.rs
rg --fixed-strings --quiet 'final FQDN observation withdrawal was not published' bins/unf-agent/src/main.rs
rg --fixed-strings --quiet '| 8.7d | Explicit wildcard discovery and live DNS lifecycle | **Verified** |' docs/development/phase8-egress-fabric-plan.md
rg --fixed-strings --quiet '| Resolver-bound wildcard observation and lifecycle | **Verified** |' docs/project-status.md
rg --fixed-strings --quiet '**Status:** Accepted and implemented for Phase 8 milestone 8.7d' docs/adr/0145-explicit-dns-discovery-authority.md

cargo test -p unf-egress wildcard_discovery_and_custom_resolver_authority_are_bounded
cargo test -p unf-egress wildcard_evidence_requires_declared_name_and_resolver_authority
cargo test -p unf-agent custom_view_observation_uses_its_bound_resolver_and_dual_stack_answers
cargo test -p unf-api --no-fail-fast
cargo test -p unf-controller egress_api --no-fail-fast
cargo clippy -p unf-api -p unf-agent -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

echo "Phase 8.7d FQDN discovery passed: wildcard names and resolver views are explicit, bounded, independently replayed, and lifecycle-gated"
