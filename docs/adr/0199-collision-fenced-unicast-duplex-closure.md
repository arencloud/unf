# ADR 0199: Collision-Fenced Unicast Duplex Closure

- Status: Accepted and implemented for Phase 9.6f
- Date: 2026-09-10

## Context

The first proof-beacon design used the IPv4 block end because legacy IPAM could
never lease it. A real UDP executor gate showed why planning evidence is not
packet evidence: Linux consistently treated that address as a subnet broadcast,
so WireGuard counters advanced while no IPv4 UDP socket received the inner
frame. The same gate also exposed strict reverse-path filtering on a newly
created WireGuard interface. IPv6 completed, but accepting family-asymmetric or
host-default-dependent behavior would make the duplex receipt false authority.

## Decision

Phase 9.6f adds **Collision-Fenced Unicast Duplex Closure**:

- IPv4 proof identity moves to the penultimate block address, an ordinary
  unicast host; new lowest-free allocation stops before it;
- legacy journals remain valid and are never force-renumbered. If a retained
  workload already owns that address, Kubernetes placement projection rejects
  encryption planning until ordinary replacement frees it, so availability is
  preserved without aliasing proof and workload identity;
- legacy `/30` blocks remain parseable but expose zero new IPv4 lease capacity,
  making the compatibility cost explicit rather than wrapping allocation;
- WireGuard provider schema v3 requires exact IPv4 reverse-path acceptance.
  The provider writes and rereads `rp_filter=0` only on its version-owned
  WireGuard interface; configuration drift rejects readback, exact replay
  repairs it, and interface deletion removes the setting with the link;
- the agent socket engine compares complete expected 72-byte request and
  response frames, not only parsed fields, before responding or completing;
- an isolated two-process gate runs the production socket engine concurrently
  in two network namespaces over both marked IPv4 and IPv6 policy tables;
- peer removal leaves the route in place but must time out closed; restoring the
  exact peer and changing the round byte must complete as fresh authority; and
- independently captured underlay traffic must contain WireGuard UDP and zero
  proof-beacon addresses, while both peer counters advance.

The live failure is part of the design record. UNF does not convert a failed
probe into a platform exception, a health heuristic, or plaintext fallback.

## Consequences

Fresh installations lose one additional IPv4 address per Node block. Existing
leases remain serviceable, but a collision visibly delays Required-encryption
activation. Reverse-path configuration is narrowly owned, capability-negotiated,
read back, and lifecycle-scoped instead of relying on a cluster-wide sysctl.

With the earlier exact controller exchange, counter-backed endpoint proof,
complete receipt join, and consuming map latch, this real executor result closes
milestone 9.6. It does not replace the independent full-runtime Kind and
OpenShift gates in milestones 9.8 and 9.9.

## Verification

`make encryption-path-live-test` inherits every prior Phase 9 encryption gate,
runs the two-ended dual-stack marked UDP executor with loss and fresh-round
recovery, repeats real provider lifecycle/readback including reverse-path drift,
checks allocation and legacy-collision behavior, and applies strict Clippy.
