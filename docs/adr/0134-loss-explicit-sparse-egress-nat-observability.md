# ADR 0134: Loss-explicit sparse egress NAT observability

**Status:** Accepted and implemented for the Phase 8.5 NAT-event slice

## Context

The gateway dataplane already preserves the exact original tuple, translated
tuple, source identity, contract revision, lease epoch, selected address and
gateway, and proof witness in connection state. The shared ABI reserved an
`EgressEvent`, but no program emitted it and no agent validated or consumed it.
Packet-by-packet export would also make event volume proportional to traffic,
creating needless pressure precisely when the network is busiest.

Observability must be useful for incident response without becoming part of
the forwarding correctness boundary. In particular, a full telemetry ring
must be visible but must never reject a packet that the NAT dataplane can
otherwise translate.

## Decision

Egress event ABI v1 is a fixed 152-byte record. It binds the monotonic kernel
timestamp, authoritative source identity, original and translated tuples,
contract revision, lease epoch, address and gateway selection indexes, primary
and standby gateway digests, and bilateral proof witness. A closed
action/reason vocabulary distinguishes translation creation, rewrite or pair
storage failure, bounded port exhaustion, and expired/corrupt pair retirement.
Userspace rejects unknown versions, sizes, protocols, families, flags,
action/reason pairs, zero authority fields, malformed IPv4 encoding, and
nonzero reserved bytes.

The packet path emits only one successful event when a new forward/reverse NAT
pair is created. Established forward and reverse packets emit nothing.
Exceptional drop and retirement paths emit a lifecycle event when complete
connection provenance is available. Kubernetes strings and policy metadata
remain downstream joins; they are never copied into the eBPF hot path.

Emission uses a dedicated non-persistent ring and per-CPU scratch record. A
two-entry per-CPU counter map records attempted events and unavailable-capacity
drops. Counter updates need no cross-CPU atomics. The agent sums those bounded
counters once per second and exports fixed-cardinality Prometheus counters for
attempts, ring drops, validated events, invalid records, creations, drops, and
expirations. Ring output failure cannot change the packet action.

## Consequences

Operators can correlate a NAT mapping with the exact lease, contract, gateway,
and proof that authorized it. Event volume tracks flow lifecycle rather than
packet rate, and telemetry loss is explicit. The agent logs validated compact
witnesses; durable NAT/failover history and enriched API/CLI joins remain the
separate Phase 8.9 operations milestone.

The event ring and counters are ephemeral telemetry maps, so the persistent
40-pin ABI v14 does not change. Restart loses unexported events and resets the
kernel counters; neither state is authority for forwarding or safe release.

`make egress-nat-observability-test` inherits the full Phase 8.5 safety chain
and adds ABI vocabulary/decoder tests, strict Clippy, verifier loading, real
IPv4/IPv6 NAT witnesses, no established-flow event amplification, and an
undersized-ring test proving exact attempted/retained/dropped accounting while
every pressure flow continues forwarding.
