# ADR 0013: Resolved-identity IPv6 dataplane

## Status

Accepted; implemented for direct-header TCP/UDP/SCTP and live verified for TCP.
ADR 0015 later added bounded extension-header traversal.

## Context

The flow ABI already reserves 16-byte addresses and an address-family field, and
identity-keyed policy entries contain no IP-family-specific fields. The missing
pieces were IPv6 Pod-address distribution, fixed-header parsing, and dual-stack
telemetry. Extending address-based prefix policy at the same time would combine
two distinct designs and make the safety boundary harder to verify.

## Decision

Identity snapshot schema v2 carries sorted IPv4 and IPv6 mappings. The agent
reconciles `IDENTITY_V4` and a fixed 16-byte-key `IDENTITY_V6` map, publishes
per-family counts, and restores both cached maps if either update fails. The TC
program parses IPv6 only when the base header points directly to TCP, UDP, or
SCTP. It resolves both addresses through `IDENTITY_V6` and reuses the same
identity-keyed active policy bank, so native policies and selector-based
NetworkPolicies have identical semantics across IP families.

IPv6 extension headers, including Fragment headers, return `TC_ACT_PIPE` without
policy evaluation or an event. `POLICY_IPV4` remains IPv4-only; IPv6 `ipBlock`
and external prefix policy were explicitly outside this slice and were added
later by ADR 0014. Flow export schema v2
requires one complete IPv4 or IPv6 address pair, and topology schema v3 publishes
both families for workload inspection.

The repeatable dual-stack kind gate requires populated IPv4 and IPv6 maps on both
agents, direct-address native allow/explicit-deny, selector-based NetworkPolicy
allow/default-deny, nonzero identity/policy provenance with address family 6,
and an enriched IPv6 flow-history record.

## Consequences

Resolved Pod-to-Pod identity policy is dual-stack without duplicating policy-map
state. Existing policy snapshot and flow-event ABIs remain unchanged. Identity,
topology, and flow-export consumers must accept their respective new schema
versions.

This slice did not claim arbitrary IPv6 packet coverage. ADR 0014 later added
bounded IPv6 prefix policy, and ADR 0015 added verifier-bounded extension-header
traversal while retaining explicit fail-open boundaries.
