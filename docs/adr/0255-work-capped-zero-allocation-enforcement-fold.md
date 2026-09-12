# ADR 0255: Work-Capped Zero-Allocation Enforcement Fold

## Status

Accepted and implemented for Phase 9.9 remediation

## Context

ADR 0252 removed policies that cannot select an exact directional identity
pair, but the remaining high-cardinality loop still invoked the general policy
explanation evaluator for every address, protocol, and port class. That API
materializes applicable, enforcement, shadow, audit, and ranked-candidate
vectors even though encryption planning consumes only the effective enforce
verdict, reason, and policy ID. On the five-Node cl02 policy cut, concurrent
Required reconciliation sustained CPU pressure and previously unbounded
allocations could grow until the host evicted the controller.

Encryption transport demand must remain exactly policy-derived. Approximating,
sampling, caching a stale verdict, or dropping a relevant class is therefore
not an acceptable performance optimization.

## Decision

Phase 9 adds the **Work-Capped Zero-Allocation Enforcement Fold**:

- the controller partitions already applicable policy references once per
  directional workload pair without cloning policy IR;
- the policy crate folds Native and Kubernetes NetworkPolicy candidates into
  the same total priority/action/policy/rule ordering without allocating a
  candidate vector;
- the compact result intentionally returns only enforce verdict, reason, and
  policy ID; shadow and audit evidence remain available through the general
  explanation evaluator and cannot alter encryption authority;
- per-class observation recording iterates the two directional decisions
  directly and performs no temporary candidate allocation;
- the complete pair work is checked against the remaining 8,388,608-class
  budget before its first class is evaluated; and
- the OpenShift primary-CNI controller receives a 256 MiB request and 2 GiB
  memory limit, so a future regression fails inside the Pod boundary instead
  of creating Node memory pressure.

The compact evaluator is compared to the complete evaluator across ingress and
egress, Native and Kubernetes origins, enforce/shadow/audit modes, explicit and
default decisions, matching and unrelated targets, and multiple ports. A
controller regression drives the observed cl02 failure scale—116 dual-stack
workloads, 133 policies, and five Nodes—through the exact sampler. The debug
test completed in 0.47 seconds with 26,252 KiB maximum resident memory when
executed directly. A separate five-Node, 120-endpoint all-cross-node Required
contract cut verifies and emits all 11,520 directional decisions.

## Consequences

- Exact policy truth is unchanged, while heap work inside the hottest class
  loop is eliminated.
- Complexity is explicit and admission-bounded before expensive work begins;
  there is no probabilistic fast path or silent policy degradation.
- The cgroup limit is a safety boundary, not evidence of scalability. Exact
  immutable Kind requalification and the complete preserved-state cl02 gate
  remain mandatory before Phase 9.9 can be marked Verified.
- Runtime `046b1b2` remains historical Kind evidence and is no longer eligible
  for final OpenShift qualification.
