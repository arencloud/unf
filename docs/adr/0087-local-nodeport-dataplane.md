# ADR 0087: Local NodePort dataplane

- Status: Accepted
- Date: 2026-08-30
- Phase: 5.5

## Context

ADR 0086 deliberately rejected Local NodePort values so they could not broaden
to Cluster selection. Local mode requires a different eligibility domain and
forward tuple: only backends placed on the receiving Node may serve a new flow,
and the backend must observe the original external source.

The existing service slot keys already include a revision-local frontend index
and service bank. Adding another persistent map would introduce an unnecessary
activation pointer and another partial-commit boundary.

## Decision

For each Local NodePort, the compiler allocates a deterministic frontend index
with the high bit set. Normal ClusterIP frontend indexes are bounded far below
that namespace. It filters the NodePort's exact backend IDs to entries that are
ready, non-terminating, and whose EndpointSlice-derived `nodeName` equals the
authenticated local Node name. Those ordered local slots are merged into the
same inactive `SERVICE_BACKEND_SLOTS` bank and count/config write as ClusterIP
state. The NodePort frontend references that service bank and local index.

The packet path validates the Local flag and creates a Local connection role.
It rewrites only the destination on the forward packet, preserving the external
source address and port. Because every selected backend is local, its reply
crosses the same Node's egress hook, which restores the exact Node address and
NodePort source. A zero-count exact Local frontend emits the existing bounded
no-backend drop; it never falls back to Cluster slots.

Established connection pairs remain valid through desired-state churn until
their protocol timeout. This preserves active traffic during endpoint placement
or readiness transitions while ensuring every new flow uses the current local
eligibility set.

## Verification

`make nodeport-local-dataplane-test` verifies the disjoint index namespace,
per-Node family-specific slot counts, merged service config count, transactional
map chain, strict lint, and all deployment renders. Verifier-loaded kernel packet
execution covers IPv4/IPv6 TCP/UDP source-preserving forward translation and
paired reverse NodePort translation.

The packet gate moves all endpoints to another Node, marks local endpoints
unready, and restores readiness/placement. It requires an established Local flow
to survive placement loss, new flows to drop in both ineligible states, and new
traffic to recover. A backend-identity ingress deny verifies that policy retains
the original external source while evaluating the translated local backend and
port. The complete Cluster and ClusterIP packet paths run in the same gate.

## Health-check boundary

Kubernetes `healthCheckNodePort` is associated with a LoadBalancer Service using
`externalTrafficPolicy: Local`; it is not an additional listener for a
NodePort-only Service. Phase 5 intentionally excludes LoadBalancer behavior, so
UNF neither synthesizes nor claims a health-check listener here. A future
LoadBalancer milestone must define and qualify that control-plane and packet
contract independently.

## Consequences

- Persistent ABI v5 does not change: Local slots use the existing service map,
  and the connection flag/reserved layout remains fixed-width and backward-safe.
- Node-address-only changes do not churn service slots; service/endpoint
  placement changes activate service and NodePort banks together.
- Generic service events still require userspace intent enrichment to classify
  Cluster versus Local. That work belongs to Phase 5.6 operations.
- Live attachment and cross-worker lifecycle remain Phase 5.7 Kind and Phase 5.8
  OpenShift qualification boundaries.
