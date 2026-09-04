# ADR 0146: Use Authority-Carved Internet classification

**Status:** Accepted and implemented for Phase 8 milestone 8.7e

## Context

An `internet: true` shortcut normally means “anything not recognized as local.”
That is unsafe in clusters with changing Pod, Service, Node, tenant, peering, or
private-cloud ranges: incomplete local inventory silently broadens permission.
Hard-coding one vendor's route table or one periodically copied special-purpose
address list creates the opposite problem—classification and policy become
inseparable, provenance disappears, and provider loss has implicit behavior.

Internet classification must remain only a destination constraint. It cannot
grant source security policy, egress-address ownership, gateway readiness,
reachability, or NAT authority, and it must not convert unresolved FQDN intent
into broad network permission.

## Decision

1. Native `EgressPolicy` adds a mutually exclusive `destinations.internet`
   selector. It names one provider-neutral classifier identity, an optional
   bounded CIDR exception set, and one explicit fallback mode. `Deny` is the
   default. `LastKnownGood` requires a nonzero maximum staleness no greater than
   one hour.
2. A classifier publishes schema-v1, algorithm-v1 complete prefix rules. Every
   rule carries an `Internet` or `NonInternet` class plus bounded human-auditable
   provenance. Source identity, source epoch, revision, observation time,
   validity deadline, canonical rule order, and the whole rule set are sealed by
   a domain-separated SHA-256 digest.
3. Authority-Carved Internet uses longest-prefix provider classification, denies
   unclassified address space, then applies policy exceptions as absolute
   subtraction. A provider's more-specific `Internet` rule cannot override an
   enclosing policy exception. The implementation hard-codes no cloud, IANA,
   RPKI, enterprise, or Kubernetes address taxonomy.
4. Current classification is usable only before its explicit deadline. A
   missing, future, or expired update either produces a deny-closed snapshot or
   reuses the exact retained classification for the configured bounded interval.
   Last-known-good snapshots commit the preceding snapshot digest and can be
   replayed against that predecessor. At the deadline, packet authority expires
   without waiting for a controller.
5. Source and gateway compilers independently verify the snapshot and lower the
   same IPv4/IPv6 longest-prefix decisions. Both families always receive `/0`
   ownership; absent/unclassified families deny instead of falling through to
   native routing. Deny-closed, expired, or no-allow classification also forces
   fenced admission.
6. Classifier positions are ordered by `(sourceEpoch, revision)`. Regression and
   different content at the same position fail closed. Updating policy
   exceptions, classifier identity, or fallback creates new policy authority and
   cannot silently reuse an incompatible snapshot.

The resulting primitive is **Authority-Carved Internet**: broad reachability is
not assumed from absence. A named authority proposes bounded positive and
negative space, while local policy can only remove from it.

## Consequences

- Clusters can consume route, RPKI, cloud, enterprise inventory, or composed
  classifiers without embedding those providers in policy, contracts, or eBPF.
- Operators see the exact classification revision, provider provenance,
  fallback state, policy-exception count, deadline, and snapshot digest in the
  compilation report.
- The same fixed-width egress ABI v4 / persistent ABI v15 maps enforce the new
  destination class; no packet parser, proxy, or per-packet userspace lookup is
  introduced.
- Default-deny is intentionally less available than an implicit route fallback.
  Bounded last-known-good behavior is opt-in and cannot outlive its configured
  deadline.
- This slice defines native intent, replay, model materialization, flow-proof
  matching, and source/gateway dataplane lowering. Authenticated durable
  classifier ingestion and a live classification lifecycle are milestone 8.7f;
  operations, scale, and OpenShift qualification remain later gates.

## Verification

`make egress-internet-classification-test` inherits the verified Phase 8.7d
gate. Focused tests cover canonical API translation, dual-stack longest-prefix
classification, unknown/private/policy-exception denial, absolute exception
precedence over more-specific provider routes, current and bounded
last-known-good deadlines, deny-closed loss, digest-linked fallback replay,
foreign classifier rejection, revision regression, same-position mutation,
source/gateway map equality, CRD equality, and strict linting.
