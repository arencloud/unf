# ADR 0144: Enforce PLR authority with autonomous dual-clock expiry

**Status:** Accepted and implemented for Phase 8 milestone 8.7c

## Context

ADRs 0142 and 0143 define Provenance-Leased Resolution (PLR), native FQDN
intent, and durable observation ownership. They intentionally stop before a
Node produces DNS evidence or packets consume it. A safe live design must not
turn controller delay, restart, clock adjustment, or DNS lookup loss into extra
network authority. It must also distinguish admission of a new flow from the
bounded draining of a flow that was established while its answer was current.

Wall-clock deadlines are portable between machines and durable checkpoints but
unsafe for per-packet comparison after clock adjustment. Monotonic deadlines
are safe on one booted Node but cannot be copied directly to another Node.
Merely deleting expired map entries from a controller reconciliation loop is
therefore insufficient: an unavailable controller could otherwise extend
authority indefinitely.

## Decision

1. Each agent is a bounded active DNS producer for exact names selected by its
   admitted source contracts in the `cluster-default` view. It queries A and
   AAAA through the first configured resolver, validates the response and
   question, follows a bounded CNAME chain, caps message and answer sizes, and
   retries over TCP when UDP is truncated. The effective TTL is the minimum of
   the address TTL and its CNAME chain. Refresh is TTL/2, bounded to 5–60
   seconds.
2. One successful round publishes a complete Node-UID-owned batch. If any
   target query fails, nothing is published: loss cannot erase or renew the
   prior ledger evidence. Removing the final target publishes one authoritative
   empty batch. Failed HTTP publication restores producer position so the same
   replacement can be retried.
3. The controller joins each desired revision with the durable observation
   revision, compiles and independently verifies one PLR snapshot per FQDN
   owner, and lowers the materialized model into both source and aggregate
   gateway inactive banks. Cache validity ends at the earliest new-flow or
   established-flow lease deadline, even when neither desired nor observation
   revision changes. Empty or below-quorum evidence produces dual-stack deny
   ownership rather than native fall-through.
4. Egress map ABI v4 retains fixed map sizes while replacing unused destination
   bytes with separate new-flow and established-flow monotonic deadlines.
   Static destinations use an explicit infinite sentinel and deny entries use
   zero. Wall-clock PLR deadlines are converted conservatively; rounding may
   close authority early but can never extend it.
5. The source eBPF path admits a new TCP SYN or UDP tuple only before the
   new-flow deadline and records bounded runtime FQDN flow memory. An exact
   established tuple may drain until its recorded deadline with the same stable
   intent digest, including after the current destination bank becomes deny.
   The gateway stores the established deadline in each persistent forward and
   reverse NAT pair. Both paths compare monotonic time on every packet and
   remove expired state without controller or agent participation.
6. Because the meaning of persistent bytes changes, persistent BPF ownership
   advances to ABI v15. ABI v14 remains a recognized exact historical 40-map
   cleanup boundary and is never adopted as current state. The Kind HA gate
   reapplies the current manifest, audits v14 cleanup before execution, removes
   only those historical pins and TCX links, and proves that v15 remains live;
   two attached ABI generations are never accepted as a qualified rollout.
7. Acknowledged Flow Twin schema v2 transports the established deadline as
   portable UNIX time. Export and import conservatively translate between each
   Node's monotonic and wall clocks; a standby never copies a foreign boot
   clock. Expired imported state remains fail-closed.

The new primitive is an **autonomous dual-clock lease firewall**: wall time
provides portable provenance, while local monotonic time is the packet-path
authority. Control-plane outage, process restart, and clock movement cannot
manufacture extra new-flow or established-flow lifetime.

## Consequences

- Exact FQDN answers can now drive transactional dual-stack source and gateway
  state while unresolved, expired, malformed, or partially refreshed evidence
  remains owned deny state.
- Established-flow grace is explicit and tuple-scoped; it is not a general
  address allowance and cannot start a new connection during drain.
- The packet path expires authority independently of reconciliation cadence.
- Source flow memory is runtime-only and therefore fails closed across program
  replacement. Gateway NAT state remains persistent and HA-portable only after
  its deadline is re-anchored locally.
- The configured resolver is an evidence source, not a workload identity or a
  DNSSEC assertion.

Active discovery of wildcard members and custom resolver views is deliberately
not manufactured from a suffix or view name; those require a later bounded
passive/explicit observation provider. A live multi-Node Kind DNS lifecycle,
internet classification/fallback, explanation, simulation, operations, scale,
and OpenShift qualification also remain separate gates.

## Verification

`make egress-fqdn-dataplane-test` inherits the complete 8.7b and measured Phase
8.6 gates. Its focused verifier checks ABI v4 and persistent ABI v15, builds the
eBPF object, exercises durable-ledger materialization, temporal lowering, the
DNS producer, and authenticated controller ingestion, then executes real
packets through the kernel.

The privileged test proves that an exact temporal destination admits a new
flow, allows only the remembered established tuple during drain, rejects a new
tuple, expires the source tuple autonomously, stores the deadline in persistent
gateway NAT state, and expires/removes reverse state without a controller.
