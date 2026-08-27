# ADR 0052: Unsupported persistent-state downgrade is rejected before BPF access

Status: Accepted and live verified on dual-stack Kind

## Context

UNF has two distinct downgrade classes. A same-tuple software rollback is
supported by the adjacent and skipped-revision gates. A binary whose compiled
persistent ABI is older than the active pin directory cannot safely infer the
newer layout. It must not open, translate, clean, or attach that state.

ADR 0051 defines the supported recovery for an ABI boundary: an orchestrated
snapshot-driven clean rebuild into the older versioned directory. That recovery
must remain distinct from directly pointing the older binary at newer state.

## Decision

A direct persistent-state downgrade is unsupported when the configured ABI
directory does not equal the agent binary's compiled ABI. The existing local
pin-path preflight is the authoritative rejection boundary and runs before
controller preflight, map creation/opening, recovery, or TC attachment.

For v4 state and a v3 binary, startup must report all three facts:

- the configured path is `/sys/fs/bpf/unf/v4`;
- the binary implements persistent ABI v3; and
- it expected a `/v3` directory.

Pinned v4 maps and TCX links remain owned by the last-known-good deployment. A
compatible v4 agent may recover them without restaging. Operators who intend to
return to v3 must use the ADR 0051 clean-rebuild sequence rather than changing
only the image.

## Qualification gate

`make kind-unsupported-downgrade-test` runs the full clean-rebuild lifecycle with
the unsupported-downgrade assertion enabled. After both v4 agents have populated
fresh state and converged, the gate:

1. computes a canonical digest over all eleven v4 maps on one node;
2. changes the DaemonSet image to the current v3 agent while deliberately
   retaining the `/v4` argument;
3. replaces that node's agent and requires the exact local ABI rejection;
4. recomputes and requires the identical eleven-map digest while the continuous
   TCP/8080 allow and TCP/9090 deny probe remains active;
5. replaces the rejected agent with v4 and requires cluster convergence; and
6. completes v3 retirement, reverse clean rebuild, scoped v4 cleanup, and final
   current-version convergence.

This test does not grant a v3 binary cleanup authority over v4. The v4 binary is
still required for exact v4 cleanup after the deliberate rebuild to v3.

## Evidence

On 2026-08-27, the complete gate passed on its first attempt from clean revision
`cc52ac52f66bc4a0500da8f4cce6069ac81f5522`.

The current controller and agent image IDs were
`0cb1af2615b14d4c63a84fd3cd02189fdeb9d3d74587a06fbdb78e1ee0526f2b`
and `1ff67fa4dea3d7f6d3c6ac557b4045a474657153d19feec0188b8bdb05916437`.
The source-labeled v4 controller and agent image IDs were
`da2dabff362fe0e85c35aa182a97fa705ffda74298537f812de0ac7aeced7213`
and `203067b66b90a60eb9138458c164aa6eabb12cdd2a0cd1a82ff3e78cf058d06f`.

The older agent logged the exact v4-path/v3-ABI rejection, the canonical v4 map
digest was unchanged, the compatible v4 agent recovered, both agents converged,
the probe recorded no allow outage or deny breach, and the fixture restored the
current v3 controller, two current v3 agents, all v3 state, and no v4 state.

The target also rebuilt the release eBPF object and current/derived release
images from the committed revision. Script syntax, formatting, diff checks, and
Make target expansion passed before the live run.

## Consequences

The supported downgrade matrix is now explicit: identical published tuples may
use the qualified software rollback; changed persistent ABIs require the
qualified clean rebuild; and a direct older-binary/newer-state pairing fails
before dataplane mutation.

The rejection is currently visible in agent logs and Kubernetes workload state.
Version-transition status, metrics, and durable classification remain milestone
2.5 and are not inferred from this gate.
