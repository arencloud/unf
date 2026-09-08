#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

rg --fixed-strings --quiet '| 8.9b | Causal explanation, failover history, and counterfactual simulation | **Verified** |' docs/development/phase8-egress-fabric-plan.md
rg --fixed-strings --quiet '| Evidence-complete egress operations | **Verified** |' docs/project-status.md
rg --fixed-strings --quiet 'private_nat_state_inferred: false' docs/adr/0154-evidence-complete-egress-counterfactuals.md
rg --fixed-strings --quiet '.route("/v1/egress/explain", post(explain_egress))' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet '.route("/v1/egress/simulate", post(simulate_egress))' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet '.route("/v1/egress/failovers", get(egress_failover_history))' bins/unf-controller/src/main.rs
