# ADR 0006: Versioned identity map and revisioned snapshot distribution

Status: Accepted for the Phase 2 identity slice; dual-stack amendment verified

## Context

TC can only classify a packet by identity after every node receives the
controller's admitted Pod-IP index. The first distribution mechanism must expose
desired/applied drift, reject incompatible schemas, survive controller process
replacement, and avoid implying that policy enforcement is already transactional.

## Decision

The controller exposes a read-only HTTP identity snapshot containing:

- a wire-schema version;
- a controller-process epoch;
- a monotonic revision within that epoch;
- sorted IPv4 and IPv6 address-to-identity entry sets.

Agents poll the internal controller Service, validate the complete snapshot, and
reconcile dedicated `IDENTITY_V4` and `IDENTITY_V6` BPF hash maps. Each
fixed-size value contains the numeric identity, map-schema version, flags, and desired revision. Agents
publish desired/applied epoch and revision plus total/per-family map entry counts
through status and Prometheus metrics. Identity snapshot schema v2 added the
separate address-family entry sets; an update is marked applied only after both
maps succeed, and rollback restores both cached families.

The epoch distinguishes a restarted controller from a stale response: revisions
must not decrease within one epoch, while a new epoch can begin at any revision.
An agent marks a revision applied only after all map operations succeed. On an
operation failure it attempts to restore its prior cached map contents.

## Alternatives

Writing ConfigMaps would add Kubernetes write amplification and GitOps ownership
ambiguity. Introducing gRPC now would add protocol/build complexity without a
measured need. Treating revision alone as globally monotonic would fail after an
in-memory controller restart. A map-in-map revision switch is appropriate for
enforcing policy state, but is unnecessary for this observation-only identity
slice.

## Consequences

Flow events can now contain nonzero source and destination identities without
making IP the trust principal. HTTP is intentionally an internal prototype
transport; authentication, authorization, backoff/jitter, and scale behavior are
required before production. Identity reconciliation can be transiently mixed
during an update, although failure rolls back best-effort and no deny verdict is
enabled. Policy enforcement still requires a transactional active/staging design;
ADR 0007 subsequently defines and implements that policy distribution mechanism.

## Open questions

- mutually authenticated controller-agent transport and node authorization;
- persisted controller epoch/allocation state and HA controller ownership;
- map pinning and agent restart recovery;
- compact prefix-policy representation for IPv6 `ipBlock`;
- map-in-map compatibility and measured policy update costs.
