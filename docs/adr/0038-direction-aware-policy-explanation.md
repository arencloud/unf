# ADR 0038: Direction- and address-family-aware policy explanation

Status: Accepted and live verified on dual-stack kind

## Context

The original `/v1/explain` contract evaluated only ingress and implicitly used a
Pod's first IPv4 address, falling back to IPv6. Once NetworkPolicy egress became
live, the same source/destination/protocol/port tuple could have independent
ingress and egress decisions. A dual-stack destination can also be included in
one egress `ipBlock` and excluded from another, so an explanation without a
concrete address family can be ambiguous or wrong.

## Decision

Explain requests accept a policy `direction` and optional `ip_family`. Ingress is
the default for backward compatibility. When no family is requested, the
controller chooses IPv4 if both Pods have it and otherwise requires IPv6 on both
Pods. An explicitly requested family must exist on both endpoints or the request
fails instead of evaluating a synthetic cross-family flow.

The controller passes the selected source address and concrete destination
address to the shared direction-aware evaluator. Responses expose the direction,
address family, source address, and destination address used for the decision.
`unfctl explain` exposes this through `--direction ingress|egress` and
`--ip-family ipv4|ipv6`.

Controller status separately reports resolved ingress and egress map-entry
counts while retaining the aggregate count. This makes a populated egress
snapshot visible without changing the per-agent transactional aggregate.

## Verification

Unit tests verify the CLI defaults and explicit egress/IPv6 parsing, plus IPv6
explicit-allow and IPv4 default-isolation explanations from accepted egress IR.
The self-cleaning Kind egress matrix requires nonzero resolved egress status and
checks IPv4/IPv6 selector allows, a port default deny, and both-family
`ipBlock` exception denies through the deployed controller and CLI.

## Consequences

Operator explanations now use the same direction and concrete family inputs as
egress lowering and enforcement. Existing clients that omit the new fields keep
the original ingress behavior, with the additional safety that both endpoints
must share the chosen family.

This does not yet add NetworkPolicy what-if simulation or retain policy direction
in historical flow keys. Those are separate schema and API changes.

ADR 0039 subsequently retained direction in flow export/history and made
historical evaluation direction-aware. NetworkPolicy what-if input remains open.
