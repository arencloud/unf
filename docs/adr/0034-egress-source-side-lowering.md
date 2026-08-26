# ADR 0034: Source-selected egress dataplane lowering

## Status

Accepted and implemented in the shared policy compiler. Snapshot distribution
and kernel enforcement remain intentionally disabled.

## Context

Ingress enforcement fixes the destination workload and matches a source
identity or address. Egress reverses the isolation axis: the selected workload
is the source, and peers—including `ipBlock`—match the destination. Reusing the
ingress address keys would therefore enforce the wrong endpoint.

TC attachment names describe the kernel hook and are not Kubernetes policy
direction. A packet can also be observed on more than one host interface, so
hook direction must not be used as a substitute for source-side isolation.

## Decision

Add direction-specific egress lowering and state entry types without changing
the currently enforced ingress snapshot:

- IPv4 keys contain source identity, exact destination address, protocol, and
  destination port. `0.0.0.0` is the arbitrary-destination fallback for an
  isolated source. Included bounded CIDR addresses get exact entries; excluded
  or outside addresses inherit that fallback.
- IPv6 keys contain source identity, destination network and prefix length,
  protocol, and destination port. `/0` is the arbitrary-destination fallback;
  CIDR and `except` boundaries plus known Pod `/128` addresses use longest-prefix
  matching.
- Known destination Pod addresses retain full endpoint metadata so Pod and
  Namespace selectors and destination-resolved named ports compile faithfully.
  Addresses present only through `ipBlock` use the external endpoint model.
- Each lowerer accepts only egress IR, validates identity/address metadata,
  preserves decision provenance and shadow decisions, sorts keys
  deterministically, and enforces the established 131,072-entry bank limit.

The new entries are not added to `PolicyStateSnapshot`, agent staging, or eBPF
maps in this slice. The controller continues using the ingress-only admission
entry point, so runtime forwarding is unchanged.

## Verification

Focused tests prove source selection, exact IPv4 allow entries, IPv4 exception
fallback denial, IPv6 prefix allow and more-specific exception denial,
Pod/Namespace destination selectors, destination-resolved named ports, and
opposite-direction rejection. Strict workspace lint and tests plus the release
eBPF build protect the existing runtime boundary.

## Consequences

The controller now has a deterministic representation ready for egress snapshot
and map ABI design without overloading ingress key meaning. IPv4 deliberately
trades bounded exact entries for a simple hash lookup; IPv6 remains compact in
an LPM trie.

ADR 0035 subsequently versioned the snapshot/map set and stages both egress maps
in the same inactive-bank transaction as ingress. TC lookup, controller egress
distribution, and live enforcement follow that transactional foundation.
