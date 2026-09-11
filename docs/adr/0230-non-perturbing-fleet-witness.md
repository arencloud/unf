# ADR 0230: Non-Perturbing Fleet Witness

- Status: Accepted and implemented for Phase 9.9 qualification
- Date: 2026-09-11

## Context

After the exact ADR 0229 tuple restored cl02 Service forwarding and all five
agents became Ready, the Phase 9.9 gate could not obtain a quiescent initial
generation. The dataplane was healthy. The observer was the fault: every
`node_exec` sample used `oc debug node`, creating a short-lived Pod. Pod watch
events advanced identity and policy inputs, so repeated generation snapshots
continuously changed the generation they were waiting to observe.

The first live execution also exposed two dormant harness defects. The
selective-Native scenario appeared after evidence emission despite its result
being consumed by that evidence, and generation/epoch waits nested a complete
360-second convergence wait inside every retry.

## Decision

Phase 9.9 adds the **Non-Perturbing Fleet Witness**. The gate creates one
dedicated, privileged, host-networked probe Pod on every explicitly selected
UNF Node through a bounded DaemonSet. Every host read or controlled link fault
executes through those stable Pods and `chroot /host`; sampling creates no new
API object and therefore cannot change the state being measured. The probe
namespace is separate from workload fixtures so exact encryption cleanup can
be proven before the observers are removed.

The selective-Native scenario now executes before ciphertext, recovery, and
evidence stages. Generation and epoch waits perform exactly one direct fleet
snapshot per retry and retain their original bounded outer deadline. Static
gate checks reject per-sample `oc debug`, nested convergence waits, or future
stage-order regression. A migration cleanup latch is armed before changing the
baseline, so interruption restores staged Native mode even when no workload
fixture has been created yet.

## Consequences

- Fleet evidence is observationally stable even when hundreds of samples are
  required on slower OpenShift hosts.
- The mechanism remains in-cluster and does not depend on SSH availability or
  external credentials.
- Probe Pods are explicit qualification resources, use the already
  acknowledged privileged boundary, and are removed before final agent and
  ClusterOperator evidence.
- Early interruption cannot leave the cluster in Required mode merely because
  fixture ownership had not yet been established.
- This changes qualification machinery only. Runtime `32b5501` and its ADR
  0229 image/evidence admission remain byte-identical.

## Verification

Shell syntax, rendered manifests, the Phase 9.9 static gate, stage ordering,
non-perturbing executor selection, and bounded-wait structure must pass before
the gate is committed. The complete cl02 qualification remains the accepting
runtime verification.
