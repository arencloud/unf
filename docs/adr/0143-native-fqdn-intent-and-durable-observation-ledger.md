# ADR 0143: Add native FQDN intent and a durable observation ledger

**Status:** Accepted and implemented for Phase 8 milestone 8.7b

## Context

ADR 0142 defines how Provenance-Leased Resolution (PLR) converts bounded DNS
evidence into temporary address authority, but it deliberately does not define
the Kubernetes API or who may submit observations. A live implementation needs
safe defaults, an unambiguous unresolved state, exact observer ownership, and
restart recovery before any DNS-derived address may reach packet maps.

Treating an absent answer as unrestricted egress would violate UNF's zero-leak
admission contract. Treating controller silence as an authoritative empty DNS
result would also erase the distinction between an observed negative result and
observation loss. Finally, identifying an observer only by a mutable Pod name or
resolver address would allow replacements or repeated responses to inherit or
inflate authority.

## Decision

1. Native `EgressPolicy.spec.destinations` accepts either `networks` or `fqdn`,
   never both. Omitting both retains the existing explicit `Any` behavior. FQDN
   intent carries an explicit resolver view, distinct-observer requirement,
   address limit, TTL cap, and established-flow grace. Defaults are one observer,
   256 addresses, a 300-second TTL cap, and a 30-second grace in the
   `cluster-default` view. All limits remain configurable but bounded by the
   generated CRD and domain validator.
2. Exact names and leading-label wildcards reuse ADR 0142 canonicalization.
   Invalid, duplicate, or unbounded values reject the whole resource. Combining
   networks and names is rejected so fallback can never be inferred accidentally.
3. An FQDN-only intent enters the domain as `DenyAll` plus its canonical name
   specification. `DenyAll` is not an empty or native destination set. Source and
   gateway compilers install `/0` ownership entries for IPv4 and IPv6 and force
   every affected source to `Fenced`, even if its admission guard was previously
   active. Missing trusted evidence therefore reaches the TC drop path instead
   of falling through to native routing.
4. Agents submit complete schema-v1 batches over the existing authenticated
   internal TLS and Kubernetes TokenReview boundary. The controller additionally
   requires the exact current agent Pod UID, authoritative Node name and UID,
   service account, namespace, and token audience. A batch is owned by one Node
   UID and one explicit resolver view.
5. Each observer/view stream is ordered by `(source epoch, batch revision)`.
   Exact replay is idempotent; regression or same-position mutation rejects the
   whole batch. Every accepted batch completely replaces that stream. A received
   empty batch is authoritative empty evidence, while no batch is observation
   loss and leaves the last known evidence unchanged without renewing its TTL.
6. The ledger and every observation are size- and time-bounded. Canonical
   ordering prevents duplicate query names and makes state deterministic. The
   ledger revision advances once per accepted replacement.
7. Controller persistence stores a schema-versioned, domain-separated SHA-256
   checkpoint beside the existing desired-state checkpoint under their shared
   ConfigMap budget. Restore validates schema, time, capacity, ordering, every
   nested observation, revision consistency, and digest before adopting any
   state.

The useful new primitive is **loss-explicit complete observation ownership**:
negative DNS evidence, stale positive evidence, and a missing observer update
remain three different states. That distinction avoids manufacturing authority
or availability from control-plane silence.

## Consequences

- Native policies have safe deterministic defaults and a strict generated CRD.
- Pod replacement cannot inherit an observation stream merely by reusing a Node
  name, and one Node cannot submit another Node's batch.
- Controller restart preserves the exact last-known observation positions and
  prevents replay regression or TTL renewal by restore.
- Unresolved intent is represented in persistent dataplane state and drops both
  IPv4 and IPv6 instead of relying on an absent LPM entry.
- Network and FQDN union/fallback remains an explicit future API decision.

This slice does not add an agent DNS-capture producer, consume the ledger to
compile PLR snapshots, refresh maps as leases age, activate DNS-derived address
entries, preserve established connections across expiry, or claim live Kind or
OpenShift packets. DNSSEC, encrypted DNS interception, malicious-authority
protection, L7 name identity, internet classification, explanation, simulation,
and platform qualification remain later gates.

## Verification

`make egress-fqdn-control-test` inherits the complete 8.7a and measured Phase
8.6 Kind gates, checks the API/CRD/documentation boundary, runs API, domain, and
controller tests, and applies strict Clippy.

Focused tests cover defaulted and bounded native translation, ambiguous
network/name rejection, canonical name handling, Node/Pod-bound authentication,
monotonic and idempotent replacement, same-revision mutation, authoritative
empty state, checkpoint replay, and source/gateway dual-stack zero-leak lowering.
