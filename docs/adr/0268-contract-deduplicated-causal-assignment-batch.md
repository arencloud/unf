# ADR 0268: Contract-Deduplicated Causal Assignment Batch

## Status

Implemented; OpenShift-first and subsequent fresh Kind qualification pending

## Context

ADR 0267's exact images passed preserved-state serial deployment on all five
cl02 Nodes with zero agent restarts and kube-proxy absent. The complete Phase
9.9 gate then stopped during the acknowledged Native-to-Required migration:
the controller repeatedly exceeded its 2-GiB memory limit before the required
generation advanced. Raising the diagnostic limit did not make the operation
bounded.

The controller was stable near 77 MiB in Native mode. Repeated serial downloads
of the 34.3-MiB policy snapshot also kept RSS stable, disproving a retained HTTP
response leak. The Required reconstruction evaluated 421,032 exact policy
classes over 115 dual-stack workloads and completed when agent authority pulls
were temporarily isolated. Code audit then found two multiplicative copies:

1. the path-proof coordinator cloned a complete multi-plan attested contract
   once for every selected plan; and
2. the assignment endpoint serialized that complete contract again in every
   endpoint work item.

For `C` contracts containing `P` selected plans, a large contract could
therefore occupy and cross the wire once per plan. The delivery lease correctly
bounded concurrent responses, but it could not make one quadratic response
safe.

## Decision

UNF uses a **Contract-Deduplicated Causal Assignment Batch** for live path-proof
work:

1. The coordinator owns each immutable contract exactly once in a digest-keyed
   ordered table. Per-plan state contains only generation, nonce-bound round,
   contract digest, and plan index.
2. Assignment batch schema v1 carries a sorted unique contract table followed
   by lightweight selections. New agents negotiate it explicitly with
   `assignmentBatchSchemaVersion=1`.
3. A consuming agent admission boundary independently verifies batch schema,
   generation, strict contract ordering, every contract digest exactly once,
   every deterministic round, complete reference coverage, and the absence of
   duplicate or unreferenced authority. Only the resulting non-serializable
   admitted object can use the fast verified-contract path.
4. Controller round construction and agent challenge/proof construction reuse
   the once-verified contract. Standalone legacy constructors retain their full
   integrity replay, so the optimization cannot bypass authority validation.
5. Contract lookup and admitted-selection membership are logarithmic. Stored
   and serialized authority is `O(contract bytes + selections)`, rather than a
   contract copy per selection.
6. The legacy unversioned response remains available only while its estimated
   expanded contract payload is at most 8 MiB. Larger legacy requests receive a
   retryable `503` directing the agent to batch schema v1; no expanded vector is
   allocated first.

The path-proof round/proof schemas, nonce and duplex-counter semantics,
WireGuard configuration, route and map authority, packet behavior, and eBPF ABI
do not change.

## Consequences

- High-cardinality regression coverage builds one 64-plan contract, proves the
  batch carries one contract and 64 selections, verifies JSON round-trip and
  mutation refusal, and requires at least a 16-fold reduction from the legacy
  expanded encoding.
- Digest mutation, duplicate contracts, duplicate selections, missing
  contracts, unreferenced contracts, foreign rounds, and cross-generation work
  fail before kernel readback or path-probe traffic.
- A controller-first Native rollout remains compatible with existing agents.
  Required activation needs a batch-capable agent when legacy expansion exceeds
  the bound; last-known-good Native authority is retained instead of risking an
  availability-driven plaintext downgrade or controller OOM.
- ADR 0267 remains immutable proof of its fresh Kind lifecycle, but cl02 rejects
  that runtime as the Phase 9.9 release candidate.
- Full workspace checks, a completely fresh Kind lifecycle, immutable public
  successor images, exact preserved-state cl02 deployment, and the complete
  OpenShift gate remain mandatory before Phase 9 is Verified.

## Follow-up review

The 2026-09-12 resume found two full-integrity calls still inside the verified
selection path. Both now use the private verified-contract constructor;
standalone untrusted inputs retain complete integrity replay. A test-only
thread-local counter proves exactly one full replay at coordinator construction
and one at batch admission for 1, 64, and 256 plans, with none added by admitted
lookups or beacon derivation. Admitted lookups reject generation substitution.
The user changed platform order to cl02 first, then fresh Kind. Both results
remain required. Post-phase work is tracked in the
[stabilization plan](../development/stabilization-and-scale-plan.md).
