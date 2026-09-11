# ADR 0234: Causal Readiness Join

- Status: Accepted and implemented for Phase 9.9 qualification
- Date: 2026-09-11

## Context

After the simultaneous cl02 reboot, all five agent reports were fresh and
converged for identity, policy, Service, and routing state. All five durable
encryption recovery plans also named one generation with no pending successor.
Those two independently true views hid a cross-plane mismatch: the encryption
generation was bound to policy revision 428 while the current agent policy cut
was revision 425. The eBPF finalizer correctly denied managed traffic, but a
gate that checked only within-view agreement could call the stale generation
ready.

## Decision

Add a **Causal Readiness Join** to every OpenShift generation wait. One bounded
retry obtains:

1. the complete fresh five-agent convergence snapshot;
2. the controller's durable egress desired revision; and
3. every Node's active encryption generation, policy, Service, and egress
   revisions from its host-local recovery plan.

The retry succeeds only when every agent's desired/applied policy and Service
revisions agree, the fleet shares one generation and one revision vector, no
Node has a pending generation, and that encryption vector exactly equals the
current policy/Service/egress cut. Revisions are monotonic, so observations
crossing a concurrent update can delay acceptance but cannot authorize an old
cut. The same predicate guards initial recovery, successor waits, and natural
epoch rotation.

## Consequences

- Encryption readiness becomes a join across control, durable host, and packet
  authority instead of three individually green indicators.
- A stale all-Native generation cannot mask fail-closed dataplane denial.
- The check adds no dataplane work and no runtime or wire-schema change.
- A concurrent update may cause one harmless retry; it cannot create a false
  positive because all compared revisions are monotonic.

## Verification

`make encryption-phase9-openshift-gate-test` requires the revision-bearing
snapshot and the shared current-cut predicate in all three bounded generation
waits. The accepting proof is the digest-pinned cl02 reboot recovery and
complete Phase 9.9 transaction.
