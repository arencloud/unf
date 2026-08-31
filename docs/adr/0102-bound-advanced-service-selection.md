# ADR 0102: Bound advanced Service selection before implementation

**Status:** Accepted and implemented for the Phase 7.1 architecture boundary

## Context

Phases 4–6 qualify dual-stack TCP/UDP ClusterIP, NodePort, and explicit-class
LoadBalancer with Cluster/Local external policy and bounded per-flow connection
persistence. The remaining master-prompt §20 behavior is not one feature:
internal strict locality, soft topology preference, ClientIP session affinity,
selection algorithms, endpoint draining, and DSR have different semantics,
state lifetime, performance, and failure boundaries.

Combining them in one unversioned backend-choice flag would make precedence,
rollback, and explanations ambiguous. Interpreting Kubernetes strings in eBPF
or letting affinity resurrect an ineligible endpoint would be unsafe. Claiming
Maglev without disruption and resource measurements would also violate the
project's evidence rules.

Kubernetes defines `internalTrafficPolicy: Local` as a strict ready local-
endpoint requirement with drop when none exists. `trafficDistribution` is a
preference and falls back; strict traffic policy takes precedence. `ClientIP`
affinity uses the client address and defaults to no affinity, with a default
10,800-second timeout when enabled. These compatibility semantics form inputs
to, not the architecture of, UNF's domain and dataplane.

## Decision

Phase 7 uses an origin-aware ordered selection pipeline:

1. strict traffic-policy eligibility;
2. optional same-Node/same-zone/cluster preference tiers;
3. eligible-set-only ClientIP affinity reuse;
4. deterministic algorithm selection for a new session;
5. independently revisioned per-flow persistence; and
6. NAT or explicitly admitted DSR forwarding.

The controller adapter defaults and validates Kubernetes fields, then emits
Kubernetes-independent schema-v4 intent with exact Node/zone provenance. The
agent compiles per-Node tiers and algorithm tables in userspace, transactionally
activates fixed-width state with the coherent service revision, and recovers it
from validated private checkpoints. The eBPF program performs bounded lookups
only; it does not interpret labels, topology strings, or variable collections.

Affinity keys include the original client address and exact Service frontend.
An affinity record is reused only when its backend remains eligible in the
currently selected tier. Established connection state remains distinct and
stronger for that exact flow. Expiry, backend lifecycle, service revision, and
capacity behavior must be bounded and observable.

Maglev is a candidate selected by evidence. A later milestone must compare it
with the current selector for distribution, remapping, memory, compile/update
latency, map write volume, and packet lookup cost over recorded backend sizes.
The result may adopt a bounded Maglev table or retain/fallback to another
algorithm for ranges where Maglev is not better.

DSR is opt-in and non-default. It cannot activate until the node proves exact
dual-stack routing, neighbor, MTU, backend VIP, policy, source-range, reverse
telemetry, health, recovery, and cleanup contracts. A capability failure keeps
the qualified NAT path active or rejects explicit DSR intent; it never silently
runs a partial direct-return mode.

Every schema/ABI transition uses capability negotiation, safe legacy projection
only when advanced intent is absent, last-known-good retention, inactive
staging, readback, atomic activation, rollback, and exact versioned cleanup.
Kind and OpenShift remain independent non-transitive gates.

## Consequences

- Strict policy, preference, session, flow, algorithm, and forwarding state are
  separate concepts and can be explained without guessing from one hash.
- Per-Node compilation costs more control-plane work but keeps topology and
  complex table construction out of the packet path.
- Client IP is an affinity key, never workload identity or policy authority.
- Maglev and DSR remain Planned after this ADR; the boundary is not an
  implementation or performance claim.
- Weighted splitting, dynamic load/latency feedback, cookie affinity,
  cross-cluster selection, production routing protocols, SCTP Services,
  fragments, generic NAT `RELATED`, Gateway API, L7, and production scale remain
  independent work.

## References

- Kubernetes, [Virtual IPs and Service Proxies](https://kubernetes.io/docs/reference/networking/virtual-ips/)
- Eisenbud et al., [Maglev: A Fast and Reliable Software Network Load Balancer](https://research.google/pubs/maglev-a-fast-and-reliable-software-network-load-balancer/)
