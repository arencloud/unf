# ADR 0207: Regression-First Performance Ledger

- Status: Accepted and implemented for Phase 9.7h
- Date: 2026-09-10

## Context

Encryption performance claims are easy to make incomparable by changing
topology, traffic, duration, MTU, or resource accounting. A single throughput
number also hides tail latency, convergence, rotation loss, map work, and scale.
Discarding a slower result would optimize documentation rather than the fabric.

## Decision

Phase 9.7h adopts the **Regression-First Performance Ledger**:

- one committed JSON record binds the exact clean harness revision, kernel,
  tooling, duration, topology, and SHA-256 digest;
- native and kernel-WireGuard paths use identical namespace placement, endpoint
  addresses, TCP concurrency, and dual-stack sample counts;
- throughput, p50/p95/p99 latency, loss, retransmits, process CPU/RSS, exact MTU
  edges, first handshake, ciphertext/plaintext capture, two-epoch rotation, four
  peer scales, and fixed BPF map activity are mandatory fields;
- evidence validation checks completeness and provenance, not a cherry-picked
  “faster than” threshold. Regressions remain first-class results; and
- optimization may coalesce Node transports, reduce delta staging, or prewarm
  epochs, but no measurement can authorize plaintext fallback for `Required`.

## Consequences

The first recorded same-host veth baseline substantially outperforms WireGuard,
and encrypted tail latency is higher. That result is visible rather than
explained away. The ledger also makes the limits explicit: client RSS does not
isolate kernel memory, a serial `wg` loop is not UNF's netlink batch, and a host
microbenchmark is not a cluster SLA. Kind and OpenShift must supply independent
end-to-end evidence before Phase 9 closes.

## Verification

`make encryption-performance-test` validates the immutable evidence digest and
all required fields after the complete Phase 9.7 recovery chain. `make
encryption-performance-live` additionally rebuilds eBPF, proves quiescent Aya
map recovery in the kernel, creates disposable namespaces, reruns the comparison,
and positively verifies scoped cleanup.
