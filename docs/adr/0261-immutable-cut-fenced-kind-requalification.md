# ADR 0261: Immutable Cut-Fenced Kind Requalification

## Status

Historical Kind qualification; rejected by the cl02 platform gate

## Context

ADR 0260 moves readiness and overload protection onto the host-network
internal API itself. It admits one authority materialization, queues none, and
fences every response by the authoritative informer-cut revision. This runtime
change invalidates the ADR 0259 image tuple and requires a completely fresh
qualification before any preserved-state OpenShift deployment.

## Decision

Revision `73057c17a424bb80b723a1a7acff4226cc4d7143` is the sole admitted Phase
9.9 candidate. Its anonymously resolvable public Linux/amd64 images are:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:e23fc788e41c459fbfcd45350642f65bd58bc7a9b18fe4976d45c89e36235d8c`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:222e252fa0513b3f77ca44e376775a869d427ef88cff0dbe66c8ec60212ea91b`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352`.

They are also published under the diagnostic tag `phase9-kind-73057c1`.
Runtime and qualifier revision
`73057c17a424bb80b723a1a7acff4226cc4d7143` passed
`make encryption-phase9-kind-test` on a newly created three-Node, dual-stack
Kubernetes v1.35.0 cluster with kube-proxy absent. The uninterrupted gate
proved:

- default-Required and explicit-selective IPv4/IPv6 PodIP and ClusterIP paths;
- 336 WireGuard underlay frames, zero Required plaintext frames, and 311
  explicit-Native plaintext frames;
- eight of eight Required fault probes blocked while eight of eight Native
  probes succeeded;
- natural two-epoch rotation, controlled agent and controller replacement, and
  295 loss-free causal operation records;
- Phase 8 egress coexistence and exact encryption/fixture cleanup; and
- complete primary-CNI rollback to the saved no-CNI baseline.

The evidence JSON SHA-256 is
`b6845fdc710e79952c84291a670c3e3e8e601e1e50e610009a22cd68a4a342cb`.
The packet capture SHA-256 is
`66341a401ce0abc9677752def14bca75dfefeeb0c187c86428d241893596972d`.

## Consequences

- ADR 0259 remains historical evidence of the internal-API admission defect;
  its tuple is not deployable as the Phase 9.9 candidate.
- The OpenShift release record and rendered overlay pin only this successor.
- cl02 must preserve the Node-local state, admit the complete cold five-agent
  retry herd without exceeding the 2-GiB controller cgroup, and pass the full
  Phase 9.9 platform gate before Phase 9 can be marked Verified.

## Platform result

cl02 proved the controller-side bound: all five cold agents converged in 81
seconds while the controller remained Ready with zero restarts and 136 MiB RSS
under its 2-GiB limit. The subsequent required serial agent replacement exposed
an agent-side liveness gap. Node-block bootstrap retries a fail-fast authority
`503`, but the following pre-BPF encryption identity bootstrap treated the same
admission response as fatal. Four steady agents could therefore keep the
replacement in kubelet restart backoff even though the controller remained
healthy. ADR 0262 extends the same bounded, fail-closed retry contract across
that second pre-BPF admission boundary.
