# ADR 0188: Placement-Truth Demand Projection

- Status: Accepted and implemented for Phase 9.5aa
- Date: 2026-09-10

## Context

The fleet plan forge accepts pure encryption facts, but Kubernetes watches are
mutable and independently revisioned. Copying Pod or Node objects directly
into transport plans could admit stale Node UIDs, unready members, host-network
addresses, IPAM drift, or an all-to-all tunnel mesh unrelated to actual policy
demand.

## Decision

UNF introduces **Placement-Truth Demand Projection**, a pure fail-closed cut:

- every member is managed, Ready, uniquely name/UID bound, and has canonical,
  non-overlapping Pod CIDRs plus an underlay endpoint;
- non-host-network workloads carry a nonzero identity, immutable workload UID,
  exact Node placement, and at least one address contained by that Node's block;
- effective L4 observations pass through the Policy-Truth Transport Quotient,
  preserving real policy IDs and honest no-policy default allow;
- only allowed cross-Node identity pairs create transport demand, and each
  demand creates both directional path facts required for a two-ended contract;
- identical Node-pair demand is coalesced before any contract or kernel work.

The projection owns no private key and mutates no Kubernetes, kernel, or BPF
state. Its output is the bounded public input to the existing fleet plan forge.

## Consequences

This prevents placement races from becoming encryption authority and avoids an
eager full mesh when policy denies or workloads are local. Controller snapshot
capture and catalog publication remain the next runtime slice.

## Verification

`make encryption-kubernetes-projection-test` inherits all earlier Phase 9
gates, proves demand-sparse default/explicit policy behavior, host-network
exclusion, dual-stack IPAM containment, unready-member refusal, overlapping
block refusal, and strict lint.
