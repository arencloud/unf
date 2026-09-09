# ADR 0181: Fleet-Synchronous Plan Cut

- Status: Accepted and implemented for Phase 9.5t
- Date: 2026-09-10

## Context

An authenticated per-Node inbox still becomes unsafe if the controller exposes
plans one by one while topology, policy, Service, egress, or key inputs are
changing. Each plan can be valid alone while the visible fleet combination
never existed as one controller decision.

## Decision

Phase 9.5t introduces the **Fleet-Synchronous Plan Cut**. A cut explicitly lists
the authoritative Node name/UID membership and exactly one verified local plan
for every member. All plans must share the cut's membership revision,
generation, policy revision, Service revision, and egress revision. Canonical
ordering and a domain-separated digest bind the complete set.

`NodeLocalPlanCatalog::publish` swaps the whole cut at one lock boundary. It
accepts an exact retry as unchanged, rejects older membership or generation,
and rejects different content at one generation as equivocation. The controller
delivery path now reads only through this catalog rather than a mutable per-Node
map.

## Consequences

- Readers observe the old complete generation or the new complete generation,
  never a partly replaced fleet.
- Explicit membership makes omission distinguishable from a smaller cluster.
- Publication memory remains bounded by Nodes plus the already bounded plans.
- The catalog starts empty and therefore returns `204` until the next slice
  builds a complete cut from authoritative inputs; it never invents defaults.

## Verification

`make encryption-plan-catalog-test` inherits the runtime inbox gate, rejects
missing membership coverage and mixed/noncanonical state, proves atomic
publish/retry/successor behavior, refuses regression and same-generation
equivocation, verifies controller use of the catalog, and applies strict Clippy.
