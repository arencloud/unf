# ADR 0054: OpenShift upgrades use digest-pinned endpoint and transition gates

Status: Accepted and live verified on dual-stack OpenShift cl02

## Context

Kind qualifies the compatibility tuple and persistent-state boundaries, but it
does not prove controller/agent transitions on RHCOS under the OpenShift SCC,
SELinux, Service CA, TokenReview, OVN, and legacy-netlink constraints. The
existing OpenShift gate used mutable development tags and tested one deployed
generation rather than an ordered N/N+1 transition.

Milestone 3 therefore requires immutable development artifacts and one
self-restoring gate that proves both endpoint platforms, every mixed pairing,
rollback, forward recovery, dataplane continuity, provenance, and operator
health.

## Decision

`make openshift-upgrade-images` accepts only a clean committed tree. It builds
the controller, agent, and test-tool images for an ancestor N and current N+1,
publishes unique revision tags to the three development Quay repositories, and
records all six content digests plus exact revisions and commit distance in a
schema-v1 local artifact. Test and deployment commands consume repository digest
references, never the tags.

`make openshift-upgrade-test` validates that the record's N+1 revision equals
the current clean commit and that N is its ancestor. It reconciles only the
checked-in exact controller RBAC and any missing durable-store ConfigMaps before
rollout. A failure trap removes test fixtures and restores the N+1 controller
and rolling N+1 DaemonSet.

The gate runs the complete adaptive OpenShift qualification at both N and N+1.
Between those endpoints it establishes a cross-worker SecurityPolicy and keeps
direct Pod IPv4 and IPv6 traffic active through:

1. N controller with N agents;
2. N+1 controller with both N agents;
3. one N and one N+1 agent;
4. full N+1;
5. one-node and full agent rollback to N under the N+1 controller;
6. complete controller rollback to N;
7. controller-first N+1 recovery with N agents; and
8. one-node and full agent recovery to N+1.

Every stage requires the exact component revision and compatibility tuple,
fresh authenticated convergence, populated dual-stack identity/policy state,
`legacy_netlink`, constrained SCC assignment, direct allow/deny behavior,
nonzero policy provenance, advancing telemetry, and healthy cluster operators.

The continuous probe treats a denied-flow success as an immediate breach. An
allowed flow is a sustained-gap breach only after three consecutive one-second
attempts with short backoff; isolated single-request loss is not attributed to
the dataplane. Breaches include UTC time and address. The endpoint gates retain
their stricter individual direct-probe assertions.

The latest result and append-only attempt history are written as schema-v1 JSON
under `.artifacts/` without credentials or projected tokens.

## Evidence

On 2026-08-27, `make openshift-upgrade-test
OPENSHIFT_KUBECONFIG=.tools/cl02-audit.kubeconfig` passed from clean revision
`9a376ae500cd7b4c84672bb77db3d3e7428a785d`, using N revision
`b078f03a109fbd17eb0b5f400d5d7aea930b95ae` at commit distance five.

The immutable N images were:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:490a9bb613d0191684bd7c0193eef73007ab81c4548b9fd58184bef409535640`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:b851163a918d716d5ac61bfea3c5706f0d3836eea0f0d009a1c2ca2a25ca5fdf`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:7f5ba616cea5d6fd239f06e0a2fed405c09433c4099b8e1c40bc1f4717e63ec0`.

The immutable N+1 images were:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:96517497e74389b5cbdcf82cb616734cbf5d5089eab0f7ec18ff5d1c7f4f5603`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:aa278b920fe84ed1f569e1ab004edcad58afc1a176bf5dde0a9034446dee99fc`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:1e10b5658d0934b24fe8475b47c437947e3cf70e320bae1109b7ff93c90f9d0b`.

The 52-minute successful run used OpenShift 4.22.9 / Kubernetes 1.35.6,
OVN-Kubernetes dual-stack cluster and service networks, two RHCOS 9.8 workers
on Linux `5.14.0-687.35.1.el9_8.x86_64`, Enforcing SELinux, native legacy
filters, and 34 healthy operators. Both endpoint suites and all ten recorded
pairing stages passed. The final Deployment and both DaemonSet Pods used the
N+1 digests, were Ready with zero restarts, and the qualification Namespaces
were removed.

The append-only history retains three earlier attempts:

- revision `3fd7e27` stopped at baseline deployment because cl02 had stale RBAC
  and no topology-history store; the gate now reconciles both prerequisites;
- revision `29694d0` was invalidated after the test operator deleted the active
  probe Namespaces during inspection; self-restoration succeeded;
- revision `29694d0` completed every transition but the one-shot continuity
  probe counted four isolated allow misses and zero deny breaches; revision
  `9a376ae` added consecutive retry plus timestamp/address diagnostics.

Failed attempts do not count as support evidence and were not removed from the
history.

## Consequences

The exact cl02 N→N+1 and N+1→N window is qualified under the named platform
invariants. This is not a transitive claim for other OpenShift releases,
kernels, architectures, CNIs, or arbitrary revision distances.

Development repositories remain non-release locations. Production publication,
signing, provenance attestation, and issuer-specific installation automation
remain separate release-hardening work.
