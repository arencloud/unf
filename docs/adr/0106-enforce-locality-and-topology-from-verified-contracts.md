# ADR 0106: Enforce locality and topology from verified contracts

- Status: Accepted
- Date: 2026-09-01
- Milestone: Phase 7.4

## Context

Milestone 7.3 distributed and durably activated a verified per-Node Network
Behavior Contract, but the packet path still consumed compatibility service
slots. Phase 7.4 must enforce strict `internalTrafficPolicy: Local` and ordered
`PreferSameNode`/`PreferSameZone` fallback for IPv4/IPv6 TCP/UDP without parsing
topology strings in eBPF, aliasing internal and external policy, or weakening
the existing policy and connection-state contracts.

The safe defaults are StableHash selection and NAT forwarding. Kubernetes
Service defaults remain Kubernetes-compatible: UNF does not silently rewrite
`Cluster` to `Local` or invent a topology preference. A supported preference is
enforced whenever the Service requests it. ClientIP affinity, Maglev, and DSR
remain unavailable until their independent milestones pass.

## Decision

The agent independently verifies the contract, resolves its ordered tiers in
userspace, and materializes only the first non-empty tier. If every tier is
empty, the final tier is retained with zero slots: strict Local therefore drops
and a fully exhausted soft preference fails explicitly. eBPF performs one
stable-hash slot lookup over that bounded selected set.

ClusterIP, NodePort, and LoadBalancer plans use distinct frontend indices and
slot namespaces. Internal and external policy can therefore differ for the same
Service without sharing an eligible set. Strict internal or external Local is
resolved before any soft preference. Slots contain only ready,
non-terminating, family- and protocol-exact backends from the verified plan.

Service map ABI v3, NodePort map ABI v2, LoadBalancer map ABI v2, and persistent
BPF-state ABI v8 assign one fixed tier byte to each frontend. Service-event ABI
v3 and persistent connection state retain the selected tier without changing
their fixed sizes. Unknown tier codes or nonzero reserved bytes fail closed.

A topology-only contract change is a dataplane change even when the Service
revision is unchanged. It stages the service and applicable external frontend
banks, reads them back, prepares the contract and Service checkpoints, and then
switches the existing activation pointers. Recovery compiles every matching
current/prepared contract and chooses only the candidate whose selection bank
and exact encoded state match the active maps. LoadBalancer reconstruction uses
the same recovered contract. Live LoadBalancer state is eagerly relinked to the
new Service bank; if its reachability projection is temporarily incompatible,
the prior Service bank remains immutable and reachable until reconciliation.
An active VIP dependency can never be overwritten as an inactive staging bank.

The existing packet order remains intact: frontend/origin classification and
strict eligibility choose the backend; ingress policy still evaluates the
original source against the translated backend identity and port; forwarding
then applies the established NAT connection contract. Existing connections
survive desired tier changes until their protocol timeout. New connections use
the newly active tier.

## Consequences

- Packet work remains constant and verifier-friendly; eBPF never scans tiers or
  parses Node/zone data.
- Strict Local cannot fall back to a remote endpoint, while soft preference
  cannot cause an avoidable drop.
- Topology-only changes are transactional and crash recoverable.
- Tier provenance is machine-readable in fixed-width kernel events.
- ABI v7 stays a recognized historical cleanup boundary; current deployments
  use `/sys/fs/bpf/unf/v8` and require a deliberate clean rebuild.
- Affinity and graceful draining are next in milestone 7.5. Maglev adoption
  remains measurement-gated, and DSR remains explicit and non-default.

## Verification

`make service-selection-dataplane-test` builds the release eBPF object for the
pinned BPF target and runs contract/dataplane tests for strict Local, ordered
same-Node/same-zone/cluster fallback, external-policy precedence, dual-stack
TCP/UDP encoding, independent external slot namespaces, lifecycle filtering,
fixed event provenance, incompatible-state rejection, recovery selection, all
7.1–7.3 prerequisites, and strict Clippy.

Live multi-Node hooks and platform-specific source/return paths remain
non-transitive Phase 7.9 Kind and 7.10 OpenShift qualification gates.
