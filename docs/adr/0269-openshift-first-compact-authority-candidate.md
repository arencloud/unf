# ADR 0269: OpenShift-first compact authority candidate

Date: 2026-09-12

Status: Deployment verified; Required migration rejected by cl02

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

## cl02 result

Qualification harness `ed70723` passed preserved-state deployment of the exact
runtime on all five Nodes, including host Service reachability, SELinux,
version/map ownership and full agent convergence. Deployment evidence SHA-256:
`a79f59fc3bb847fcdd790e4ff901f3a62b3a67828f40da50bd171dcbb1762a27`.
The complete workspace suite also passed 720 tests with 22 privileged tests
intentionally ignored by the generic invocation.

The complete platform gate failed at `explicitly-acknowledged-required-migration`:
the generation did not advance before the convergence deadline. All six UNF
Pods had zero restarts. One controller cgroup observation reported a
213,843,968-byte peak and zero OOM events at the 2-GiB limit; 36 metrics samples
for that Required controller peaked at 211,456 KiB working set and approximately
1.37 CPU cores. These are diagnostic observations, not a heavy-load benchmark.

Agents repeatedly reported encrypted probe rendezvous timeout and insufficient
remaining round lifetime. Inspection found per-frame linear work lookup,
full-pending-set completion scans and all-pending retry bursts before receive
processing, plus repeated complete-cut verification on each proof submission.
These are candidates for correction, not a claim that every timeout has one
proven cause. Recovery persistence also briefly exceeded the 900,000-byte
compressed bound (about 912,110 bytes); a later cut fit at 791,134 bytes. This
transient recovery gap remains tracked. No bound was increased.

The gate collected ignored local diagnostics and restored Native mode. Kind is
still pending for this successor. Neither milestone 9.9 nor Phase 9 is Verified.
