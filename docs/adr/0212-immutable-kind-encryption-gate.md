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

The fresh three-Node dual-stack Kubernetes v1.35.0 qualification was repeated
on 2026-09-11 after the Phase 9.9 pre-attachment safety correction. Runtime and
qualification revision `1dbef4d6a75a6c2b97c276267f7b43d95b6cae41` produced
schema-v1 evidence with SHA-256
`d73bd08db6992c8ddd1855f0f5173d6fa39d91b46fee389500e41ae2f4da8708`.
Its packet capture has SHA-256
`2f944751d201d33efddf417dd842d20aa0ce95a82d83da10df9a3b7389492ed7`
and records 280 WireGuard frames, zero Required-path plaintext frames, and 312
explicit Native-path plaintext frames. Required traffic failed closed for all
eight link-loss probes while all eight Native probes remained live. Natural
rotation, one exact agent replacement, controller replacement, loss-free
operations through sequence 328, the committed performance ledger, Phase 8
egress coexistence, exact encryption cleanup, and complete primary-CNI rollback
all passed.

This result supersedes the earlier pre-correction `6fe2a92` runtime evidence;
that tuple must not be promoted to OpenShift. ADR 0214 records the correction
and its causal safety boundary.

This evidence qualifies controlled single-agent replacement and separate
controller replacement. It deliberately does not claim that simultaneously
restarting every encrypted endpoint preserves an already established path;
that event removes both ends of the live proof rendezvous and therefore fails
closed until fresh mutual authority is available.
