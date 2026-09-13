# ADR 0297: Partial Frontier Receipt Recovery Gap

Date: 2026-09-13

Status: live Kind failure diagnosed; regression and repair pending

## Observed failure

After the expanded cl02 pass in ADR 0296, fresh three-Node dual-stack Kind uses
the same `571379d` images. OCI export/import preserves all three Quay manifest
digests; fully qualified tags avoid the historical containerd import-alias
failure. Agent startup is held until controller bootstrap configuration is
ready. All four component containers start with zero restarts.

The Phase 9 base overlay initially selects Required; the Native-only gate
refuses preflight before creating a fixture. Changing the baseline to Native
replaces the controller during early frontier progression. The retried gate
passes local listeners but fails its first allowed same-Node request. All three
agents nevertheless report normal policy/Service convergence. The fixture is
removed; the Kind cluster and durable state are retained for recovery testing.

| State at capture | Generation |
|---|---|
| Restored controller frontier | `1789273418666` |
| Restored fleet plan | `1789273423267` |
| Control-plane Node admitted cursor | `1789273418666` |
| Both worker admitted cursors | `1789273423267`, each naming exact predecessor `1789273418666` |

Only control-plane and worker receipts for the older frontier were persisted;
worker2's receipt is missing. Worker requests reject delivery of that older
frontier, while complete-cut admission recovery cannot combine the old and new
Node cursors. This leaves the predecessor acknowledgement barrier unsatisfied.
Concurrent key catch-up warnings are retained, not silently attributed as the
cause or dismissed by altering key lifetimes.

Private evidence includes the controller ConfigMap checkpoint, public-only
Node recipient/checkpoint projections, version/image records, logs and the
failed fixture under `.artifacts/s1-native-571379d-*`. No private key authority
file was read or modified, and no journal, map or rule was reset.

## Required repair boundary

An authenticated durable admission of an exact successor also proves that
same Node admitted the successor's exact predecessor. Recover only that Node's
missing predecessor receipt, after current Pod/Node UID, membership, checkpoint
integrity and exact predecessor publication validation. Prepared facts alone,
foreign Nodes, skipped/mutated predecessors and unrelated generations must
never supply receipts. Do not infer admission of the successor on lagging Nodes
or synthesize a complete newer frontier from partial evidence.

Add a deterministic mixed-cursor/lost-receipt regression before implementation,
keep replay idempotent and checkpointed, and avoid cloning large payloads merely
to recover a fixed-width receipt. Test the repaired runtime on cl02 first, then
recover this retained Kind state and rerun the expanded traffic gate. Fresh-Kind
and full Phase 9 lifecycle qualification still remain required. Native continuity
under benign metadata churn, Required locality/replica/reply coverage, and S1–S5
remain open. A controller checkpoint or Pod-readiness pass is not packet proof.
