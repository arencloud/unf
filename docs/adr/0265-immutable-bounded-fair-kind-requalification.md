# ADR 0265: Immutable Bounded-Fair Kind Requalification

## Status

Historical Kind qualification; rejected by the cl02 platform gate

## Context

ADR 0264 replaces zero-waiter shedding with a bounded FIFO admission domain,
preserves exactly one expensive authority materialization, and separates the
constant-work compatibility and status control lane. This changes both runtime
images and requires an independent fresh-cluster qualification before cl02 may
consume the successor.

## Decision

Revision `3ffa0a6479dc2260f1989ddf95204a26a9e2ea3a` is the sole admitted Phase
9.9 candidate. Its anonymously resolvable public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:c233bec3188b060b2704b6fdf84ed8e118812f05aebd33515e6aed44c6ec619a`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:9a395b22f8976479bc5333a8450b9dd41ff7a73d049f3cdcaa4d30d97c10b37e`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

They are also published under diagnostic tag `phase9-kind-3ffa0a6`. Runtime and
qualifier revision `3ffa0a6479dc2260f1989ddf95204a26a9e2ea3a` passed
`make encryption-phase9-kind-test` on a newly created three-Node, dual-stack
Kubernetes v1.35.0 cluster with kube-proxy absent. The uninterrupted gate
proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 392 WireGuard underlay frames, zero Required plaintext frames, and 312
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  282 loss-free causal operation records;
- 32 bounded performance requests against the committed regression ledger;
- Phase 8 egress coexistence and exact encryption/fixture cleanup; and
- complete primary-CNI rollback to the saved no-CNI baseline.

The evidence JSON SHA-256 is
`d4e3b1c51b220a0bdf584a19e3331b175147f9685296dfa4e995952fd97a95e5`.
The packet capture SHA-256 is
`57f87a0e6de3259c96ac2be0735ac14ae65a7252958f55a35f8d42af25252b50`.

## Consequences

- ADR 0263 remains the historical proof of causal startup retry and the
  zero-waiter starvation found on cl02; its tuple is no longer deployable.
- The release record and OpenShift overlay pin only this successor.
- cl02 must accept exact preserved-state serial replacement and then pass the
  complete Phase 9.9 gate before Phase 9 can be marked Verified.

## Platform result

The preserved-state controller-first and five-Node serial transition passed:
all five agents converged without restart, kube-proxy remained absent, and the
controller stayed at zero restarts with 94 MiB observed RSS. The complete gate
then changed the baseline to Required and exposed a narrower lifetime gap. The
controller was repeatedly OOM-killed at its 2-GiB limit before the first new
generation could advance. Its retained fleet cut was only 22,179,791 bytes
uncompressed, so one durable plan was not itself near the limit.

The materialization permits were released as soon as Axum constructed a
response. Buffered policy and plan bodies remained live while agents received
them, allowing later requests to materialize additional large bodies outside
the admission domain. ADR 0266 extends both permits through response-body
completion or disconnect. The gate restored Native mode and all six UNF pods
returned Ready.
