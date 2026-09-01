# ADR 0104: Verify Network Behavior Contracts before activation

**Status:** Accepted and implemented for the Phase 7.2a reference boundary

## Context

Schema v4 can express internal locality, topology preference, ClientIP
affinity, selection algorithm, and NAT/DSR forwarding intent. Milestone 7.3
must turn that global intent plus Node and EndpointSlice placement into
different selection state for every Node. A syntactically valid snapshot is
not enough to prove that a per-Node plan retained strict `Local` behavior,
preserved the ordered preference fallback, referenced only eligible backends,
or required capabilities actually advertised by its destination Node.

Distributing opaque tables would also weaken UNF's explanation and recovery
model. A corrupted checkpoint, incompatible producer, partial transaction, or
compiler defect could otherwise activate state that cannot be traced back to
one exact source/topology revision. Conventional hashing and Maglev address
backend choice and disruption; they do not establish this higher-level
selection contract.

## Decision

UNF introduces schema-v1 **Network Behavior Contracts**. `unf-service` owns the
Kubernetes-independent reference validator. A contract binds:

- source epoch, Service revision, topology revision, contract revision, Node
  name/UID/zone, and explicit Node capabilities;
- exact ClusterIP, NodePort, or LoadBalancer frontend identity and the normalized
  policy, preference, affinity, algorithm, and forwarding intent;
- ordered same-Node, same-zone, and cluster backend tiers compiled for that
  Node; and
- independently reproduced invariant and bounded failure-envelope results.

Issuance canonicalizes plan/backend ordering, validates every frontend against
the normalized Service snapshot, derives the strict policy before any soft
preference, requires exact ready/non-terminating backend sets with matching
family/protocol and placement, and rejects missing StableHash/Maglev or NAT/DSR
capabilities. Strict `Local` has only a same-Node tier and therefore cannot
silently broaden to zone or cluster fallback.

The failure envelope deterministically records current behavior and single
endpoint, Node, and zone loss for every plan. Each observation distinguishes an
available fallback tier, an intentional strict-policy drop, and general
unavailability. The complete observation count and an explicit truncation bit
are retained when the fixed 4,096-observation evidence bound is reached. This is
a bounded availability diagnostic, not an SLO, capacity model, or exhaustive
multi-failure reachability proof.

The canonical plan and complete contract use domain-separated SHA-256 digests.
An agent can independently validate source binding, normalized ordering,
invariants, failure observations, and both digests before staging or activation.
A 128-bit domain-separated decision witness binds one exact frontend plan to the
complete contract digest for later event/explanation joins. Witnesses are
provenance identifiers, not credentials or policy authority.

Milestone 7.2a changes no BPF map, packet behavior, agent checkpoint, controller
transport, status, or platform claim. Milestone 7.3 must distribute these
contracts, validate them at the agent, bind checkpoints and staged state to
their digests, and activate only a coherent verified revision. Later milestones
extend the contract evidence for affinity records, draining, measured Maglev,
and the complete DSR host-safety model without weakening this base.

## Consequences

- Selection state becomes hash-addressed, reproducible, mutation-detecting, and
  explainable before it becomes a dataplane transaction.
- A legacy consumer cannot claim convergence for contract-required state.
- Control-plane CPU and evidence storage increase, but observations are bounded
  and the eBPF path receives only fixed-width state and compact witnesses.
- A contract produced and checked by UNF detects drift, mutation, incompatible
  state, and invariant violations. It does **not** mathematically prove the
  compiler correct; property, mutation, packet, recovery, and platform tests
  remain required.
- Dynamic latency/load feedback, automatic remediation, combined-failure proof,
  and production availability claims remain outside this milestone.

## References

- Kubernetes, [Virtual IPs and Service Proxies](https://kubernetes.io/docs/reference/networking/virtual-ips/)
- Eisenbud et al., [Maglev: A Fast and Reliable Software Network Load Balancer](https://research.google/pubs/maglev-a-fast-and-reliable-software-network-load-balancer/)
- Fogel et al., [A General Approach to Network Configuration Analysis](https://www.usenix.org/conference/nsdi15/technical-sessions/presentation/fogel)
- Khurshid et al., [VeriFlow: Verifying Network-Wide Invariants in Real Time](https://www.usenix.org/system/files/conference/nsdi13/nsdi13-final100.pdf)
