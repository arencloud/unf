#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

rg --fixed-strings --quiet 'EGRESS_INTERNET_CLASSIFICATION_ALGORITHM_AUTHORITY_CARVING_V1' crates/unf-egress/src/internet.rs
rg --fixed-strings --quiet 'pub provenance: String' crates/unf-egress/src/internet.rs
rg --fixed-strings --quiet 'previous_snapshot_digest' crates/unf-egress/src/internet.rs
rg --fixed-strings --quiet 'EgressInternetAuthority::DenyClosed' crates/unf-egress/src/dataplane.rs
rg --fixed-strings --quiet 'pub internet: Option<EgressInternetControls>' crates/unf-api/src/lib.rs
rg --fixed-strings --quiet '| 8.7e | Authority-Carved Internet classification | **Verified** |' docs/development/phase8-egress-fabric-plan.md
rg --fixed-strings --quiet '| Provider-neutral internet classification and fallback | **Verified** |' docs/project-status.md
rg --fixed-strings --quiet '**Status:** Accepted and implemented for Phase 8 milestone 8.7e' docs/adr/0146-authority-carved-internet-classification.md

cargo test -p unf-egress internet --no-fail-fast
cargo test -p unf-api --no-fail-fast
cargo test -p unf-controller egress_api --no-fail-fast
cargo clippy -p unf-api -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

echo "Phase 8.7e internet classification passed: prefix authority is provider-neutral, policy-subtractive, replayable, temporal, and fail-closed"
