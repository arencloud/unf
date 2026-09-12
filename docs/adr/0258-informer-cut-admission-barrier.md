# ADR 0258: Informer-Cut Admission Barrier

## Status

Accepted for Phase 9.9 requalification

## Context

The immutable `a728017` runtime passed the complete fresh Kind transaction and
staged cleanly on cl02. All five agents converged and the controller remained
near 140 MiB. The Phase 9.9 gate then restarted the controller while five agents
were retrying their authenticated state pulls. The controller made its Pod
Ready immediately after spawning Kubernetes watchers, before their initial
Pod, Namespace, Node, Service, EndpointSlice, SecurityPolicy, NetworkPolicy,
and EncryptionPolicy relists formed one complete authority cut.

That admitted a recomputation stampede over partial, repeatedly changing
snapshots. The process was deterministically killed at approximately 2.09 GiB
RSS under a 2-GiB limit, 8.37 GiB under an 8-GiB diagnostic limit, and 15.4 GiB
under a 16-GiB diagnostic limit. Disconnecting the controller Service from the
agents allowed the same process to finish all relists at 71–147 MiB. Reconnecting
all five agents after the relists completed remained at 73–148 MiB with no
restart. The planner and steady-state pull paths were therefore not the failed
boundary; premature Service admission was.

The OpenShift gate also counted 360 iterations as a six-minute timeout even
though each iteration could perform five sequential bounded remote reads. Its
failure cleanup was correct, but the nominal timeout was not a wall-clock
bound.

## Decision

The controller implements the **Informer-Cut Admission Barrier**:

- connected startup begins with one fixed eight-bit pending mask for every
  authoritative watcher needed by agent snapshots and encryption planning;
- each watcher asserts its bit on `Init` and clears it only on `InitDone`;
- controller readiness remains false while any bit is present, so Kubernetes
  does not publish the Pod as a ready Service endpoint and agents retain their
  last-known-good dataplane state;
- a later relist withdraws readiness until that replacement cut is complete,
  preventing a partial relist from becoming distribution authority; and
- the barrier is constant-space and independent of object, Node, policy, and
  retry cardinality. It queues no per-agent payload and changes no BPF ABI.

The OpenShift qualification waits use a shared real `SECONDS` deadline.
Generation convergence, agent convergence, epoch rotation, replacement, and
owned-state cleanup cannot multiply that budget by the cost of a remote
observation.

## Consequences

- Startup availability waits for one complete informer cut instead of exposing
  repeatedly invalid partial authority. Health remains available while
  readiness truthfully stays false.
- Existing agents continue enforcing their durable last-known-good state and
  retry normally; no plaintext fallback or empty-policy snapshot is published.
- Relist completion, rather than retry arrival order, is the causal admission
  point. This removes a cluster-size-dependent memory race without increasing
  the controller cgroup.
- Runtime `a728017` remains valid historical Kind evidence but is rejected as
  the final cl02 candidate. The barrier successor must pass the complete fresh
  dual-stack, kube-proxy-free Kind lifecycle, be published by immutable digest,
  and then pass the complete cl02 gate before Phase 9 is Verified.
