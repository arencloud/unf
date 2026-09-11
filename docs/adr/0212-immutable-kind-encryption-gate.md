# ADR 0212: Immutable Kind Encryption Qualification Gate

- Status: Accepted and implemented for Phase 9.8e
- Date: 2026-09-11

## Context

The Phase 9 components had independent contract, kernel, packet, recovery, and
performance evidence, but the final Kind acceptance criteria were not one
repeatable cluster transaction. Manual probes could omit one IP family, confuse
the default-required and selective modes, inspect an unowned link, or lose the
relationship between the tested source revision, runtime image IDs, capture,
and cleanup result.

## Decision

UNF adds one destructive, dedicated-cluster qualification gate that:

- refuses any non-Kind context, kube-proxy presence, pre-existing encryption
  intent, non-dual-stack Node, or non-exclusive primary-CNI installation;
- records the full source revision and runtime image IDs before mutation;
- proves cluster-wide default Required first, then explicitly changes to the
  Native baseline and applies a namespaced Required pair;
- exercises direct PodIP and ClusterIP paths over IPv4 and IPv6;
- captures the worker underlay and requires WireGuard frames, no selected
  Required inner frames or HTTP markers, and positive Native inner frames;
- lowers only an exact UNF-owned WireGuard alias, requiring Required failure and
  simultaneous Native success before restoring it;
- requires agent and controller replacement recovery, a natural bounded epoch
  rotation, loss-free operations history, the committed performance ledger,
  and the existing Phase 8 egress lifecycle on the same runtime;
- proves owned encryption interfaces and routing rules disappear after intent
  deletion; and
- optionally ends by running the existing exact primary-CNI rollback gate.

The Phase 9 overlay uses a 600-second test-key lifetime, a 480-second
rotate-before window, five seconds of deterministic jitter allowance, and a
30-second drain. The 120-second rotation cadence remains observable while a
restarted agent has a generous validity window for controller reconstruction.
These are qualification timings, not production defaults.
Evidence is atomically written as schema-v1 JSON; it contains public runtime
and causal facts but no private key material.

## Consequences

Kind qualification is now reproducible and fail-closed rather than a checklist
of unrelated observations. The gate intentionally owns and ultimately tears
down its dedicated cluster state. It does not itself assert OpenShift behavior;
milestone 9.9 independently reuses the exact qualified image tuple on cl02.

## Verification

`make encryption-phase9-kind-gate-test` validates the rendered overlay, shell
syntax, and required gate boundaries. `make encryption-phase9-kind-test` runs
the live qualification and writes `.artifacts/phase9-encryption-kind.json`.
