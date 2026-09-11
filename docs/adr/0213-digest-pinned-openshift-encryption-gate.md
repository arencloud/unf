# ADR 0213: Digest-pinned OpenShift encryption qualification gate

- Status: Accepted and implemented for Phase 9.9 qualification
- Date: 2026-09-11

## Context

The Phase 9.8 Kind result proves the complete encryption transaction on a
dedicated three-Node Linux fixture. It cannot establish RHCOS, enforcing
SELinux, CRI-O, five-Node convergence, OpenShift SCC behavior, or cross-worker
traffic on the independent cl02 platform. cl02 is also an existing UNF
installation, so switching its baseline to Required during the image rollout
would violate the accepted no-surprise upgrade boundary.

## Decision

UNF publishes the exact Kind-qualified controller, agent, and test-tools images
to public immutable Quay digests. A Phase 9.9 overlay upgrades cl02 in Native
mode through the existing controller-first, MachineConfig-aware, one-Node-at-a-
time agent workflow. The qualification then requires three matching explicit
values: infrastructure identity, disposable-fixture acknowledgement, and
Native-to-Required migration acknowledgement.

The live gate must independently prove:

1. five Ready dual-stack UNF primary-CNI Nodes, `networkType: None`, kube-proxy
   absence, RHCOS, enforcing SELinux, CRI-O, and the exact image/schema tuple;
2. an explicitly acknowledged cluster baseline transition from Native to
   Required, followed by an explicit selective Required pair under Native;
3. cross-worker IPv4/IPv6 PodIP and ClusterIP traffic for both Required and
   Native paths;
4. `br-ex` underlay capture with positive WireGuard frames, zero selected
   Required plaintext, and positive intentionally Native plaintext;
5. Required failure alongside Native success while an exact alias-owned
   WireGuard link is down;
6. natural two-epoch rotation, one controlled agent replacement, a separate
   controller replacement, loss-free causal operations, and final traffic;
7. exact Namespace, intent, interface, and policy-route cleanup after returning
   the upgraded cluster to Native; and
8. five-agent convergence, all Nodes Ready, and no new unhealthy
   ClusterOperator relative to the captured baseline.

The atomic evidence includes only public keys' schema/revision facts and image,
platform, causal, packet-count, cleanup, and operator results. It does not copy
Node-local key material or key checkpoints.

## Consequences

The OpenShift claim is independent and reproducible rather than inherited from
Kind or Phase 8. The upgrade remains native after qualification; changing a
production upgrade to Required remains an explicit operator decision. A
controlled single-agent replacement and separate controller replacement are in
scope. Simultaneously replacing every endpoint of an encrypted path is not
claimed because the live proof rendezvous correctly fails closed until fresh
mutual authority exists.

## Verification

`make encryption-phase9-openshift-gate-test` validates the guarded script,
release record, immutable render, and required assertions. The live deployment
and qualification are `make encryption-phase9-openshift-deploy` and
`make encryption-phase9-openshift-test` with the cl02 kubeconfig and exact
infrastructure acknowledgements.
