#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null

rg --fixed-strings --quiet 'pub const EGRESS_EVENT_ABI_VERSION: u16 = 1;' \
    "${project_root}/ebpf/unf-ebpf-common/src/lib.rs"
rg --fixed-strings --quiet 'static EGRESS_EVENTS: RingBuf' \
    "${project_root}/ebpf/unf-ebpf-tc/src/main.rs"
rg --fixed-strings --quiet 'static EGRESS_EVENT_COUNTERS: PerCpuArray<u64>' \
    "${project_root}/ebpf/unf-ebpf-tc/src/main.rs"
rg --fixed-strings --quiet 'full telemetry ring must never stop NAT forwarding' \
    "${project_root}/bins/unf-agent/src/main.rs"
rg --fixed-strings --quiet '"unf_egress_event_ring_drops"' \
    "${project_root}/bins/unf-agent/src/main.rs"
rg --fixed-strings --quiet '| Loss-explicit sparse egress NAT observability | **Verified** |' \
    "${project_root}/docs/project-status.md"

"${project_root}/hack/verify-egress-gateway-nat.sh"

echo "Phase 8.5 NAT observability passed: proof-bound sparse lifecycle ABI, exact semantic decoding, fixed-cardinality metrics, and non-blocking ring-loss evidence are verifier-proven"
