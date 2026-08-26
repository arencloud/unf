# ADR 0031: Direction-aware policy IR and evaluation

## Status

Accepted and implemented for the userspace policy foundation. Egress API
translation and dataplane enforcement remain in progress.

## Context

The original shared policy model was destination-selected and implicitly
ingress-only. Implementing Kubernetes `NetworkPolicy` egress by reusing that
implicit contract would either select the wrong workload or risk lowering
source-side isolation into destination-side BPF keys. The policy direction must
be explicit before the compatibility adapter and dataplane can grow safely.

The TC flow ABI already reports ingress and egress hook directions. Policy IR,
decisions, and the userspace evaluator did not preserve that distinction.

## Decision

`PolicyDirection` is a shared `repr(u8)` type with stable ingress and egress
values matching the existing flow ABI. `PolicyIr` and `PolicyDecision` carry the
direction explicitly. Deserializing an older IR or decision without the field
defaults to ingress, preserving the only behavior those records could represent.
Ingress decisions omit that default from JSON to keep the current explanation
and simulation response shapes stable; egress decisions serialize it explicitly.
Native `SecurityPolicy` and the current Kubernetes ingress translator emit
ingress IR.

The direction-aware evaluator selects the destination for ingress and the source
for egress. It considers only policies in the requested direction, so ingress and
egress isolation cannot affect one another. The original `evaluate` entry point
remains an ingress wrapper for existing controller, explanation, simulation, and
lowering callers.

The current identity, IPv4, and IPv6 dataplane compilers remain ingress-only and
reject any egress IR with a typed error before producing entries. Egress will get
source-side lowering and enforcement in a subsequent slice; it is not encoded in
the destination-oriented maps by approximation.

## Verification

Shared ABI tests pin the numeric direction values and eBPF structure layout.
Policy tests prove source-selected egress allow/default isolation,
direction-to-direction isolation, ingress wrapper compatibility, explicit egress
decision serialization, legacy ingress deserialization, and typed rejection by
all three ingress dataplane compilers.

Run `cargo test -p unf-common -p unf-ebpf-common -p unf-policy --all-features` for
the focused gate. The repository-wide formatting, lint, test, and eBPF build
gates also cover this contract.

## Consequences

Userspace can now represent and evaluate policy isolation in either direction
without duplicating the policy engine, while all existing ingress callers keep
their behavior. Unsupported egress lowering fails closed at an explicit boundary.

ADR 0032 subsequently added userspace `spec.egress` translation and Kubernetes
`policyTypes` defaulting behind the ingress-only controller admission boundary.
ADR 0033 subsequently added destination-address and egress `ipBlock` evaluation.
This ADR does not claim source-side BPF maps or hook enforcement,
direction-bearing retained flow history, simulation/status integration, or live
kind/OpenShift egress qualification. Those remain the next egress milestone
slices.
