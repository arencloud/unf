# ADR 0269: OpenShift-first compact authority candidate

Date: 2026-09-12

Status: Implemented; platform qualification pending

## Context and decision

The user requires cl02 feature qualification before Kind. Runtime
`cfff9c36c29a7c306a6dbf0457b85ce8c1065632` completes ADR 0268's once-verified
selection path. The release record pins public controller and agent images
built from that runtime and explicitly records Kind as pending. Historical
ADR 0267 evidence is not inherited by this successor.

The encryption library passed 105 tests (two privileged tests intentionally
ignored by the generic invocation); full workspace formatting and strict
all-target/all-feature Clippy passed. Qualification-order regression and the
OpenShift static gate passed. Public image metadata is checked before rollout.

## Qualification boundary

Deploy on the existing five-Node cl02 with preserved state, restore the normal
2-GiB controller memory limit and remove temporary debug logging, then execute
the complete acknowledged encryption gate while collecting resource samples.
Existing unhealthy ClusterOperators must be recorded, not represented as a
healthy-cluster baseline. Required activation, ciphertext, selective Native
traffic, failure closure, rotation, recovery and cleanup must actually pass.
Only then execute the fresh Kind lifecycle on the same runtime.

Neither Phase 9 completion nor heavy-load readiness is claimed by publishing
these images. Subsequent measured work and explicit limits are tracked in the
[stabilization plan](../development/stabilization-and-scale-plan.md).
