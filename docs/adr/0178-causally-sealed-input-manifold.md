# ADR 0178: Causally Sealed Input Manifold

- Status: Accepted and implemented for Phase 9.5q
- Date: 2026-09-10

## Context

The snapshot-first compiler needs contracts, readiness, revisions, identity
decisions, and transport bounds together. Polling these independently would let
an agent observe a combination that never existed at the controller: for
example, a new policy decision with an old key epoch, or a partial contract set
with a new generation number. Existing CNIs often hide this class of skew behind
eventual convergence, but Required encryption cannot safely allow that window.

## Decision

Phase 9.5q introduces the **Causally Sealed Input Manifold**: one strict,
Node-scoped, secret-free `NodeLocalPlanSnapshot` that advances all compiler
inputs as a single digest-bound cut.

The snapshot independently enforces:

- one immutable Node name/UID recipient and nonzero membership/generation,
  policy, Service, and egress revisions;
- exactly one active epoch and at most one draining epoch;
- self-verifying attested contracts whose local Node, policy revision, path,
  peer, key, mark, route table, and MTU facts agree;
- a nonzero readiness digest for every included epoch;
- exactly one required decision reference for every contract plan, with no
  missing, duplicate, foreign, or mismatched identity pair;
- no transport reference on a native decision; and
- canonical ordering plus a domain-separated digest and strict unknown-field
  refusal.

The snapshot may reconstruct ephemeral compiler inputs, but it is not kernel or
map authority. Exact local key possession, Linux staging/readback, policy-route
readback, controller echo admission, and the consuming Aya latch remain
mandatory downstream.

## Consequences

- Independent watches cannot create a mixed encryption generation.
- Retry and caching need only one bounded digest comparison.
- A large identity graph remains exact while the kernel plan stays
  Node-cardinality bounded.
- The wire object contains no private key, kernel readback, route permit,
  activation latch, or reusable capability.
- Authenticated controller distribution and durable agent adoption of this
  manifold are the next slice; no running agent integration is claimed here.

## Verification

`make encryption-plan-manifold-test` inherits Phase 9.5p, proves permutation-
independent issuance and end-to-end exact-readback compilation, rejects partial
coverage and unknown fields, checks the secret-free schema structurally, and
applies strict Clippy.
