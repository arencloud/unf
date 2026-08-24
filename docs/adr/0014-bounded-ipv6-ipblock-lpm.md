# ADR 0014: Bounded IPv6 `ipBlock` LPM enforcement

Status: Accepted and live verified

## Context

Expanding IPv6 CIDRs into exact source addresses is not viable. The existing
IPv4 compatibility map deliberately permits only 1,024-address blocks, while a
normal IPv6 subnet can contain vastly more addresses. IPv6 `ipBlock` must still
preserve Kubernetes exceptions, additive policies, native-policy precedence,
known-Pod selector behavior, provenance, and atomic policy updates.

## Decision

Preserve IPv6 CIDRs and exceptions as prefix boundaries in policy IR. The
controller evaluates one representative address for each semantic region and
emits decisions into `POLICY_IPV6`, an LPM trie. Its 192-bit lookup data places
64 exact bits first—destination identity, destination port, protocol, and bank—
followed by the 128-bit source address. Stored prefix lengths are therefore
`64 + source_prefix_len`.

The compiler emits every relevant protocol/port decision at each boundary so a
more-specific exception can override a broader allow. Known Pod addresses add
`/128` boundaries with their workload metadata; external regions use identity
zero. A `/0` boundary carries compatibility isolation for arbitrary IPv6
sources. One IPv6 block is limited to 1,024 CIDR boundaries, and the final map is
also limited to 131,072 entries per bank.

Policy snapshot schema v3 carries identity, exact IPv4, and IPv6 prefix entries.
The agent stages and validates all three inactive banks before one
`POLICY_CONFIG` activation write, then garbage-collects the old bank.

## Consequences

- Normal IPv6 prefixes, including `/0`, do not require address expansion.
- `except` and overlapping policies retain longest-prefix semantics with the
  shared evaluator as the source of truth.
- The policy-map ABI advances to version 2 and requires an eBPF object containing
  `POLICY_IPV6`.
- IPv6 extension headers remain fail-open and are a separate milestone.
- LPM trie support requires Linux 4.20 or newer.
