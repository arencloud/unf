#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

rg --fixed-strings --quiet '| 8.9c | Upgrade, recovery, compatibility, and exact cleanup | **Verified** |' docs/development/phase8-egress-fabric-plan.md
rg --fixed-strings --quiet '| Causal egress upgrade and recovery | **Verified** |' docs/project-status.md
rg --fixed-strings --quiet 'pub egress_distribution_schema_version: u16' crates/unf-state/src/lib.rs
rg --fixed-strings --quiet 'classify_egress_recovery(' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet 'phase8_current_cleanup_is_exact_atomic_in_scope_and_rollback_safe' bins/unf-agent/src/main.rs
rg --fixed-strings --quiet '**Status:** Accepted and implemented for Phase 8 milestone 8.9c' docs/adr/0155-causal-egress-recovery-vector.md
