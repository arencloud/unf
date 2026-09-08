# ADR 0152: Correlate BFD through a Causal Failure Lattice

**Status:** Accepted and implemented for Phase 8 milestone 8.8e

## Context

BFD can detect loss far sooner than a BGP hold timer, but a BFD Down event does
not prove why a path failed, whether a gateway is fenced, or which system may
own its addresses. One physical gateway, link, or fabric failure can also emit
many BFD, RIB, and dataplane symptoms. Counting those symptoms or observer
replicas as independent votes creates fast but unsafe failover. Restoring a
path immediately after the first Up event creates a second failure mode: flap
storms caused by congestion, scheduler delay, or transient packet loss.

UNF needs fast detection without converting a routing daemon or Kubernetes
health into ownership authority, and it must retain useful causal provenance
instead of presenting operators with a cascade of duplicate alarms.

## Decision

1. UNF uses GoBGP v4.9.0's native RFC 5880 asynchronous, RFC 5881 single-hop
   BFD implementation. UNF does not implement the wire protocol or state
   machine. BFD is explicit per peer because both endpoints must agree; when
   present, an IPv4 port-3784 single-hop transport, 100 ms–10 s
   transmit/receive intervals, and detection multipliers 2–50 are enforced. A
   configured peer is ready only when BGP is Established and BFD is Up. One
   session may protect both negotiated IPv4 and IPv6 route families.
2. Complete BFD readback is canonical and digest-sealed. It binds the exact BGP
   configuration, authenticated Node name and UID, source epoch/revision,
   observation time, every configured peer/failure domain, local and remote
   states/diagnostics, discriminators, transition count, and packet counters.
   Missing, extra, duplicate, malformed, or drifted peers fail closed.
3. Agents publish the self-contained configuration and snapshot over the
   existing authenticated internal TLS channel. The controller independently
   verifies both, binds evidence to authoritative Pod placement and Node UID,
   admits only finite-age evidence, and rejects epoch/revision regression or a
   same-position mutation. Evidence is ephemeral and never persisted as
   ownership authority.
4. The Causal Failure Lattice (CFL) is enabled for all admitted BFD evidence. A
   digest-sealed plan binds the exact DQR plan and path set. Signals identify
   one of three planes: fast liveness, route control, or dataplane. Each carries
   bounded dependency atoms such as `gateway/<uid>`, `peer/<address>`, and
   `fabric/<domain>`.
5. Dependency sets that overlap are transitively collapsed into one causal
   incident. Many BFD observers of the same gateway remain one liveness plane,
   not a manufactured quorum. A path is suppressible only after Down evidence
   from at least two distinct planes. BFD alone yields `Suspect/Investigate`.
6. CFL uses fast failure and deliberately slow recovery. Two Up planes must
   remain stable for a configured recovery hold, and signals exceeding a flap
   transition budget remain `Unstable`. Partial corroboration recommends only
   the exact path set for suppression. Corroborated loss of every planned path
   recommends source fencing.
7. CFL output is advisory by construction: its schema contains no address
   acquisition, lease, ownership, or promotion capability. Actual failover
   continues through the Phase 8.6 proof chain: every source fences, the old
   owner is proven absent or independently fenced, replacement ownership reads
   back, DQR converges, and only then may a sealed activation grant exist.

## Consequences

- Detection can be sub-second without letting one daemon, replica set, or
  correlated failure domain self-authorize a takeover.
- Operators receive one incident graph for one causal fault, with exact affected
  paths and evidence digests, instead of a misleading alarm count.
- Timer drift, stale evidence, restart replay, optimistic recovery, and
  correlated-observer inflation are deterministic failures rather than timing
  accidents.
- GoBGP's current native BFD has no authentication, echo mode, or demand mode.
  Production deployments must protect the routing segment and use conservative
  timers appropriate to CPU and loss characteristics. Cryptographic BFD is not
  claimed by this milestone. IPv6 BFD transport also remains unqualified after
  its live v4.9 fixture did not establish; UNF rejects it instead of advertising
  false coverage.

## Verification

`make egress-bfd-test` runs digest/replay, causal-collapse, single-plane denial,
multi-plane suppression, all-path fencing, recovery-hold, flap-budget, typed
GoBGP mapping/readback, authenticated controller/agent compilation, and strict
Clippy gates.

The live gate creates two gateway and two external fabric speakers on an
isolated dual-stack network. IPv4 single-hop BFD sessions carry both IPv4 and
IPv6 route families. After exact CRC-bearing dual-stack routes are visible, the
gate stops one real gateway speaker. Both
fabrics must report BFD Down, the failed route must disappear, the independent
gateway path must remain, duplicate liveness symptoms must collapse into one
incident, and route-control corroboration must recommend suppression of exactly
the failed path without issuing promotion authority. Recovery hold and flap
damping are independently replayed under deterministic domain tests.

References: [GoBGP BFD](https://github.com/osrg/gobgp/blob/master/docs/sources/bfd.md),
[RFC 5880](https://datatracker.ietf.org/doc/html/rfc5880), and
[RFC 5881](https://datatracker.ietf.org/doc/html/rfc5881).
