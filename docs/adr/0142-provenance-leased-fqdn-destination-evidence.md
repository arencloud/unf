# ADR 0142: Use provenance-leased FQDN destination evidence

**Status:** Accepted and implemented for Phase 8 milestone 8.7a

## Context

An L3/L4 egress fabric ultimately enforces addresses, while an FQDN policy is
written against names whose answers change over time and by resolver view.
Treating every observed answer as an immediate allow creates avoidable failure
modes: a compromised or stale observer can broaden access, split-horizon
answers can leak between tenants, a long TTL can outlive intent, wildcard
suffixes can match unintended names, and bounded map pressure can silently
discard only part of the desired policy.

DNS also cannot establish workload or application identity. Once an address is
admitted, an L3 packet does not reveal whether the application used the name or
the literal address, and one address may host several unrelated names. UNF must
not describe those limits as stronger L7 or DNS identity enforcement.

## Decision

UNF introduces schema-v1 **Provenance-Leased Resolution (PLR)** as the first
Phase 8.7 contract. It performs expensive temporal and name processing in
bounded userspace and produces independently replayable address leases for
later transactional dataplane lowering.

1. Policy names are canonical lowercase ASCII DNS names. Unicode must arrive in
   explicit DNS A-label form. An exact pattern matches only itself. A wildcard
   may appear only as the complete leading `*.` label, requires at least a
   two-label suffix, matches one or more complete labels below that suffix, and
   never matches the apex or a partial suffix.
2. Each observation carries an observer UID, resolver address, explicit DNS
   view, source epoch, observation revision, controller-comparable timestamp,
   bounded canonical-name chain, addresses, and TTLs. A canonical-name loop,
   duplicate answer, unspecified address, unbounded TTL, excessive future clock
   skew, or duplicate observer/query record rejects compilation.
3. Resolver views are isolation domains. Evidence from another view is counted
   for diagnostics but never joins the selected view's quorum. Observers are
   counted by distinct UID, not by resolver address, response count, or answer
   count.
4. For a name/address pair supported by `q` observers, PLR sorts each capped
   answer expiry and sets the new-flow deadline to the `q`-th latest expiry.
   Therefore the lease remains active only while at least the configured quorum
   supports it. Zero-TTL answers grant no lease. The original capped TTL,
   timestamp, canonical chain, observer, view, epoch, and revision remain in the
   lease as explanation and replay evidence.
5. After the new-flow deadline, a bounded policy grace may authorize only an
   already established flow. New flows fail closed. At the grace deadline all
   flows fail closed; time never creates or renews authority.
6. The complete deterministic lease set must fit the policy's explicit address
   capacity. Overflow rejects the entire compilation. PLR never evicts a subset
   or converts an FQDN constraint to unrestricted internet access.
7. Schema, algorithm, canonical policy, ordered leases, distinct-observer
   quorum, capped expiries, grace, provenance, capacity, and domain-separated
   SHA-256 digest are independently replayed before a snapshot becomes a typed
   verified value. Decisions accept only that verified type and retain the
   snapshot digest and matched name patterns.

PLR's configurable observer quorum is the useful new primitive in this slice:
operators may choose one trusted observation where availability matters, or
require agreement among multiple independently authenticated observation
points for sensitive destinations. Unlike a simple union cache, disagreement
narrows authorization and remains visible.

## Consequences

- Stale answers, observation loss, view disagreement, zero TTL, and capacity
  pressure have deterministic fail-closed outcomes.
- Established connections may drain for an explicit bounded interval without
  allowing new connections on expired DNS evidence.
- Split-horizon DNS can be used without merging private answers across policy
  views.
- Canonical-name targets need not match the original policy suffix; the queried
  name is the selector and the complete chain remains provenance. This supports
  normal CDN indirection without silently turning the CDN's domain into a
  wildcard.
- A packet sent directly to an IP that currently has a DNS-derived lease is
  indistinguishable from a packet produced after a name lookup. Explanation
  says `DNS-derived address evidence`; it never claims application-name
  identity. Explicit network/internet fallback will remain a separate policy
  choice.

This slice is a provider-neutral domain contract. It does not yet claim native
API fields, authenticated DNS observation transport, durable refresh/recovery,
transactional agent maps, packet enforcement, DNSSEC validation, DoH/DoT
interception, protection against a malicious authoritative DNS server, L7 SNI
or HTTP enforcement, live Kind behavior, or OpenShift qualification. Those are
subsequent Phase 8.7 gates.

## Verification

`make egress-fqdn-evidence-test` inherits the complete measured Phase 8.6 Kind
HA gate, verifies the documentation boundary, runs eight focused domain tests,
and applies strict Clippy to `unf-egress`.

The tests cover label-bounded wildcard and apex behavior, canonicalization,
quorum-th expiry and TTL caps, active-to-draining transitions, IPv4/IPv6 views,
split-horizon non-merging, visible zero-TTL/below-quorum outcomes, atomic
capacity rejection, duplicate-observer resistance, digest mutation, expiry,
and no allow fallback without DNS evidence.
