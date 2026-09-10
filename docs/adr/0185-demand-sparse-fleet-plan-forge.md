# ADR 0185: Demand-Sparse Fleet Plan Forge

- Status: Accepted and implemented for Phase 9.5x
- Date: 2026-09-10

## Context

The plan catalog requires exact fleet membership, but not every current worker
owns a workload that needs a cross-Node encrypted path. Treating an idle worker
as absent breaks complete-cut safety; fabricating a workload contract or tunnel
wastes kernel state and creates false authority.

Plan production also must not accept public keys and readiness as independent
inputs. Doing so would permit a valid contract to be joined to another key
frontier during rotation or recovery.

## Decision

Phase 9.5x introduces the **Demand-Sparse Fleet Plan Forge**.

One producer consumes a complete public-key transparency cut and derives key
facts, common epoch, readiness digests, and key revision directly from it. It
then compiles every Node contract from one model/fact/revision snapshot and
publishes the results only through one `NodeLocalPlanFleetCut`.

Node-local plan snapshot schema v2 adds an explicit `Active` or `Dormant` mode.
An active member must carry exactly one active epoch and exact decision-to-plan
coverage. A dormant member must carry no epoch, required decision, contract, or
transport authority while remaining present in fleet membership. This keeps the
control plane exact without allocating interfaces for zero demand.

Only a common, lifetime-valid `MutuallyAttested` or already `Active` public
epoch can enter the producer. Prepared, draining, partial, mixed-epoch, expired,
or ambiguous key cuts fail before any catalog mutation. Private keys and local
kernel capabilities are not inputs.

## Consequences

- Idle workers cost constant small catalog state and zero WireGuard interfaces.
- Fleet membership and key readiness remain exact even when encryption demand
  is sparse or moves between Nodes.
- Plan schema v2 makes dormant intent explicit instead of overloading an empty
  or malformed active plan.
- This slice implements the pure authoritative producer. Kubernetes fact
  projection, controller invocation, and the Node-local runtime compiler remain
  subsequent independently gated slices.

## Verification

`make encryption-fleet-plan-producer-test` inherits the reciprocal key witness
gate and proves atomic all-member production, active path plans, authority-free
dormant Nodes, common ready-key requirements, canonical catalog validation, and
strict Clippy for the encryption domain.
