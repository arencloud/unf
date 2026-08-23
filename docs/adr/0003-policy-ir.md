# ADR 0003: One deterministic policy IR

Status: Accepted

## Context

Native SecurityPolicy, Kubernetes NetworkPolicy, CLI simulation, and future APIs
must not produce separate enforcement behavior. Decisions must be reproducible and
explainable.

## Decision

Convert external APIs into a Kubernetes-independent `PolicyIr`. Retain rule
provenance. Rank lower numeric priorities first, deny before allow at a tie, then
stable IDs. Audit is non-enforcing; shadow evaluation is a separate reported
verdict. Property-test order independence.

## Alternatives

Evaluate CRDs directly, preserve controller arrival order, or create independent
native/Kubernetes engines. Each would introduce schema coupling or nondeterminism.

## Consequences

The compiler can run without a cluster and supports explanation/simulation. The
future BPF encoding is an output of this IR, not a second semantic model. Policy
semantics become an API contract requiring deliberate versioning.

## Open questions

Per-rule priority, egress rules, tiering/inheritance, and Kubernetes NetworkPolicy
union semantics in the compatibility adapter.
