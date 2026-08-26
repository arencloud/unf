# ADR 0036: Source-selected egress TC lookup

## Status

Accepted and implemented. Controller egress distribution remains gated.

## Context

Policy ABI v3 provides transactional egress maps, but declaring those maps does
not define packet lookup precedence or composition with ingress isolation. TC
attachment direction is a property of the host interface traversal and cannot
stand in for Kubernetes policy direction; one packet may also be observed on
multiple host interfaces.

## Decision

The existing TC program evaluates both policy directions from the parsed packet:

- ingress selects the destination workload and retains the established source
  identity/address lookup order;
- egress selects the source identity, then checks the concrete IPv4 destination
  before the arbitrary-destination address fallback, using exact port,
  protocol-wildcard port, and global wildcard precedence for each address;
- IPv6 egress uses longest-prefix destination matching for the same exact,
  protocol-wildcard, and global-wildcard dimensions;
- every value must match the active policy ABI and revision before it can affect
  forwarding.

Ingress and egress isolation compose as an AND boundary: a valid deny from
either direction returns `TC_ACT_SHOT`. If both directions produce valid allows,
ingress is the deterministic reported decision; if one direction alone applies,
that decision is reported. The event direction is the selected policy direction.
Only no-policy/fail-open observations retain the TC hook direction.

Malformed values, absent maps/configuration, revision mismatches, unknown
selected identities, and unmatched entries fail open. The controller continues
emitting empty egress lists, so this slice cannot change live forwarding by
itself.

## Verification

The workspace format, strict lint, unit-test, and release eBPF gates pass. A
first verifier load rejected an aggregate optional-decision merge because one
LLVM-generated register path was not provably initialized; the implementation
was rewritten to use fully initialized fixed-layout decisions. The corrected
program loaded on both nodes of the dual-stack Kind cluster.

The complete `make kind-test` gate then passed the upstream-aligned IPv4/IPv6
ingress matrix, protocol and extension-header coverage, transactional fault and
map-pressure rollback, offline-controller last-known-good recovery, durable flow
history, and TCX/legacy attachment replacement. Populated egress lookup and
allow/drop provenance are intentionally deferred to the controller-distribution
slice.

## Consequences

The kernel forwarding path is ready to consume the already transactional egress
entries without treating host hook direction as policy semantics. The next
slice can remove the controller admission gate and qualify real source isolation,
peer/port forms, dual-stack lifecycle, and recovery.

The single-decision Flow ABI cannot preserve both provenances when ingress and
egress simultaneously apply; it records the deterministic decisive direction.
Stateful established/related reply handling also remains outside this slice and
must be addressed before claiming complete upstream egress conformance.
