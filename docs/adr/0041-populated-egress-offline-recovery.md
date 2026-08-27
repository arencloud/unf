# ADR 0041: Populated egress recovery with the controller offline

Status: Accepted and live verified on dual-stack kind

## Context

Pinned last-known-good recovery already proved that an agent replacement could
adopt active identity and ingress policy maps while the controller was offline.
Egress added two maps to the same transactional bank, but previous recovery tests
ran after focused egress fixtures were deleted. They therefore proved structural
support for the eleven-map ABI without proving that populated source-selected
IPv4 and IPv6 state survived a real source-node agent replacement.

## Decision

The complete Kind gate now installs a temporary egress NetworkPolicy selecting
`frontend/client` and allowing direct TCP/8080 to `backend/server`. It requires
nonzero controller-resolved egress entries and converged agent revisions before
stopping the controller.

With the controller absent, the gate replaces the agent on the source workload's
Node. The replacement must become Ready from pinned state, expose the exact active
policy revision, and log nonzero recovered `EGRESS_IPV4` and `EGRESS_IPV6` active
bank counts. Direct Pod-address TCP/8080 must remain allowed on both families and
TCP/9090 must remain denied. The controller is then restored, agents reconverge,
and the temporary policy is deleted with another revision convergence check.

Recovery logging now reports per-map active-bank counts for identity, ingress
IPv4/IPv6, and egress IPv4/IPv6 policy state. This is observability only; it does
not change map contents, the persisted ABI, or readiness rules.

## Verification

Agent unit, lint, and workspace gates remain clean. `make kind-test` passed its
complete ingress and egress matrices, fault injection, existing destination-node
offline replacement, the new populated dual-stack source-node replacement, and
post-recovery cleanup. The durable-history and legacy-netlink follow-up gates also
passed; the history gate now requires the selected probe key's last-received time
to fall inside its exact test window, avoiding stale-key false positives after an
expanded suite.

## Consequences

The last activated egress revision is now qualified for source-node agent
replacement during controller outage, including live forwarding and explicit
proof that both family maps were populated after recovery.

Service ClusterIPs remain outside this direct Pod-address policy qualification.
UNF is not a CNI or service-NAT implementation, and selector-based egress entries
resolve workload addresses rather than pre-DNAT Service VIPs.
