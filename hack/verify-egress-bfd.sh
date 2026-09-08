#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

rg --fixed-strings --quiet 'causal-failure-lattice-v1' crates/unf-egress/src/failure_correlation.rs
rg --fixed-strings --quiet 'BFD evidence does not match the authenticated Node identity' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet 'read_bfd_snapshot' bins/unf-agent/src/main.rs
rg --fixed-strings --quiet '| 8.8e | BFD and failure-correlation integration | **Verified** |' docs/development/phase8-egress-fabric-plan.md
rg --fixed-strings --quiet '**Status:** Accepted and implemented for Phase 8 milestone 8.8e' docs/adr/0152-causal-failure-lattice.md

UNF_BGP_INJECT_FAILURE=1 hack/verify-egress-bgp.sh
