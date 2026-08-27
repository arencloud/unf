# ADR 0056: Phase 3 closes on a traceable cross-platform release audit

Status: Accepted and live verified

## Context

Master prompt section 103 requires NetworkPolicy compatibility, shadow
policies, a policy-simulation foundation, better topology state, and historical
flow export before work may move toward a full CNI. Each capability was already
implemented and individually verified, but closing the phase also required one
consistent requirements and limitations audit plus current committed-revision
regression evidence.

This decision closes only Phase 3. It does not declare UNF production-ready,
broaden any support-matrix row transitively, or approve the separate full-CNI
architecture gate.

## Decision

Phase 3 is Verified only while all of the following mappings remain true:

| Section 103 requirement | Repository evidence | Classification |
|---|---|---|
| NetworkPolicy compatibility | The pinned Kubernetes audit classifies all 49 bounded L4 scenarios; the complete Kind and OpenShift gates exercise supported dual-stack ingress and egress selectors, ports, protocols, named ports, ranges, `ipBlock`, defaulting, lifecycle, provenance, explanation, simulation, and recovery | Verified |
| Shadow policies | Native shadow enforcement and observation-weighted online/offline impact analysis are covered by the workspace and Kind gates; ADR 0044 defines the bounded history contract | Verified |
| Policy simulation foundation | Simulation schema v4 accepts native and Kubernetes policies, evaluates direction-aware dual-stack topology and retained history without mutating live revisions or forwarding, and is exercised on Kind and OpenShift | Verified |
| Better topology state | Topology schema v3 and history schema v1 retain dual-stack workload, Service, EndpointSlice readiness/placement, bounded queries, checkpoint restore, and restart fencing; ADR 0045 defines retention limits | Verified |
| Historical flow export | Flow schema v3, history schema v4, checkpoint schema v2, CLI queries, and optional bounded external HTTP export pass retention, recovery, pressure, authentication, and exact-key restore gates; ADR 0046 defines external-export limits | Verified |

The authoritative Phase 3 work breakdown contains 42 Phase 3 deliverables. All
42 are Verified after this closure row moves to Verified. The adjacent
full-CNI row remains Gated and is not counted as a Phase 3 deliverable.

## Release-readiness evidence

The implementation revision for the closure regression is
`43320db6792c519208fe130f535043c4860127a2`. The immediately adjacent baseline
is `6fcea3150410bd783d6c2c153ca76acb0b9a15b1`.

The following gates passed against the implementation revision:

- `make fmt-check lint test`, `make ebpf`, base and OpenShift manifest renders,
  and `make support-matrix-check`;
- `make kind-test UNF_POLICY_TRANSITION_ATTEMPTS=90`, including the complete
  dual-stack ingress, egress, recovery, history, external export, TCX, and
  legacy-netlink suites;
- `make kind-scale-failure-test`, using the deterministic four-Namespace,
  24-workload, eight-NetworkPolicy profile. Initial apply took 11 seconds,
  three churn cycles took 40 seconds, simultaneous two-agent recovery took 33
  seconds, controller reconvergence took 7 seconds, and telemetry drop delta
  remained zero, all within the recorded budgets;
- `make kind-upgrade-test`, which passed N/N, controller-first N+1/N, serial
  mixed agents, full N+1, agent rollback/forward recovery, controller rollback,
  uninterrupted enforcement, and telemetry continuity; and
- `make openshift-upgrade-test
  OPENSHIFT_KUBECONFIG=.tools/cl02-audit.kubeconfig`, which passed from
  2026-08-27 21:34:40 UTC through 22:21:43 UTC.

The isolated additional-release gate remains independently qualified at
`da733591b23618bff1001769ae02d30dc1c3e2ce`: Kubernetes 1.34.8 on two Debian 13
Kind nodes passed the full endpoint/recovery, TCX/legacy, and adjacent-revision
transition suites. ADR 0055 retains its exact platform record and all seven
attempts.

The closure OpenShift run used cl02 with OpenShift 4.22.9, Kubernetes 1.35.6,
OVN-Kubernetes dual-stack networking, two selected RHCOS 9.8 workers on Linux
`5.14.0-687.35.1.el9_8.x86_64`, native legacy-netlink attachment, Enforcing
SELinux, and 34 healthy operators. Both full endpoint gates, controller-first
compatibility, both worker-serial mixed directions, complete agent/controller
rollback, and forward recovery passed. The final N+1 Pods were Ready at the
current digests and the qualification fixtures were removed.

The immutable N images were:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:e1852c5acc7cc160dcbc71067357d1fc9161d5230fcd4893b3aee55a9b3aff2b`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:70b413c46645ce7a8410642b2a0fd2b295b9bfd07c415d949cbfc3b034da0276`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:d9676e9ca3e5125feae6cab8684419182cc51a28f0542e03041348fa2aa91c1a`.

The immutable N+1 images were:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:6da8594c5208fd24e5ac0127c161844de8b4f7d86a1539da2b17adc572a02570`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:bd88849ec12d97bf6bb27a83455d0a1011c13a5a3a9eff5504498837dfb208ef`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:ec35f4534fd860140cb03c4fbb76067d4db952e6350488d3a34e81637f4e343b`.

## Retry record

The closure regression preserves failures rather than presenting only the final
pass:

- the first complete Kind attempt at `6fcea31` passed behavior but did not
  observe the sampled protocol-only allow provenance after one request;
  `43320db` made the bounded check regenerate the exact allowed tuple on every
  polling attempt, after which the complete endpoint gate passed;
- the Kubernetes 1.34 platform history contains six failed attempts and one
  pass, with every failure classified in ADR 0055; and
- the OpenShift append-only history contains three earlier failed development
  attempts, the prior pass at `9a376ae`, and the current closure pass at
  `43320db`. The closure run itself passed on its first attempt.

Failed attempts remain diagnostic evidence and never count as a qualified
support result.

## Limitation audit

The following boundaries remain intentional and are reflected in the status,
roadmap, and support matrix:

- NetworkPolicy support is the documented bounded ingress and egress L4 slice;
  unbounded compiler output and non-L4 related-traffic semantics remain outside
  it.
- Support applies only to the four exact platform rows. Other Kubernetes or
  OpenShift releases, kernels, operating systems, architectures, CNIs, and
  larger or mixed cluster shapes are not inferred.
- Digest-pinned UNF component upgrade and rollback is qualified on the exact
  cl02 window. Upgrading the OpenShift platform itself is not qualified.
- Persistent-state clean rebuild and rejection boundaries are qualified; byte
  migration between incompatible persistent ABIs is not.
- The published Quay artifacts are development images. Production repositories,
  signatures, attestations, installer automation, and a production-scale claim
  remain separate release-hardening work.
- Full CNI/IPAM, veth or netkit ownership, routing/MTU, service load balancing,
  encryption, L7, and multi-cluster transport remain gated or planned.

## Consequences

Phase 3 changes from In progress to Verified. The phase is complete at its
documented bounded scope, and the closure regression is reproducible from the
listed commands and immutable evidence.

Full-CNI foundation work may begin only after a separate explicit architecture
approval covering ownership, coexistence, upgrade, rollback, and uninstall.
Phase 3 completion alone does not grant that approval.
