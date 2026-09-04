# ADR 0141: Close live measured egress HA

**Status:** Accepted and implemented for Phase 8 milestone 8.6f

## Context

Milestones 8.6a–8.6e proved placement, promotion, continuity, exclusive
ownership, and durable transaction semantics independently. They did not prove
that authenticated watched agents could execute the complete protocol on a real
multi-Node dual-stack dataplane. A production path also has to handle a Node
that is simultaneously a source and an egress gateway, restart in the middle of
source retirement, structured source identities in JSON checkpoints, and the
difference between Kubernetes health evidence and isolation authority.

## Decision

UNF completes one promotion as an ordered proof-carrying transaction:

1. The controller sends self-contained, Node-UID-bound certified-plan
   challenges over the authenticated internal API.
2. Every exact source atomically fences its complete managed table before the
   former owner may snapshot state. Restart recovery may reissue source-fence
   evidence only after exact active-bank BPF readback matches the sealed durable
   retirement manifest.
3. The former owner exports complete forward/reverse Acknowledged Flow Twin
   pairs for each moved CCR shard. The standby imports them into the persistent
   LRU and acknowledges exact BPF readback before they are eligible for cutover.
4. The former owner revokes and reads back exact address absence. Replacement
   gateways acquire only their assigned shards, and static reachability records
   an exact compare-and-swap handoff.
5. A source-specific cutover binds acknowledged live twins to the inactive
   source bank. Terminal active-bank evidence is required before the controller
   removes the promotion.

Checkpoint schema v5 retains the complete transaction including terminal source
activation. Structured recipient-to-cutover state is serialized as a canonical
sorted entry list; an empty object remains accepted solely for compatibility
with checkpoints written before a cutover could be encoded. Duplicate or
non-empty legacy objects fail closed.

The runtime-only eBPF dispatcher is versioned as
`SERVICE_DATAPLANE_TAIL_CALLS_V2`. Its eight slots isolate IPv4/IPv6 source
classification from gateway NAT classification. A gateway classifier passes a
valid flow selected for another gateway to the dedicated source classifier, but
gateway ingress never recursively re-steers. This preserves mixed-role Nodes
without increasing the persistent ABI-v14 map set and keeps each program inside
the kernel verifier's stack bound.

Kubernetes `Ready=False` or `Ready=Unknown` starts investigation and source
fencing but never proves old-owner isolation. Graceful drain uses exact kernel
address absence. Abrupt loss cannot advance until the old owner returns and
completes the proof chain or a separately admitted infrastructure fence exists.

## Consequences

- Phase 8.6 has repeatable bounded availability evidence rather than only a
  planner or protocol claim.
- Existing flows can survive a graceful handoff when their complete pair is in
  the acknowledged snapshot; the unacknowledged asynchronous tail remains
  measurable and may be disrupted.
- Minimum-disruption membership is sticky. A recovered Node is not
  automatically given ownership back, and an abrupt recovery may leave reduced
  redundancy until a later explicit rebalance feature is designed.
- Empty AFT streams are valid for shards with no live state. Qualification seeds
  a TCP mapping and selects its externally observed owner so nonzero replication
  is deterministic rather than probabilistic.
- This decision does not claim production-scale availability, controller HA,
  BGP/EVPN/ECMP/BFD, a non-static reachability provider, OpenShift behavior, or
  zero packet loss.

## Verification

`make egress-ha-kind-test` inherits every 8.6a–8.6e domain, controller, agent,
strict-Clippy, eBPF, and transaction gate, loads the current images, and runs
`hack/verify-kind-egress-ha.sh` on three-Node Kubernetes 1.35 dual-stack Kind
without kube-proxy.

The closing run rooted at revision `68de7abf0826efd15db65cf777e85e8b5e00b11d`
recorded:

- 80 successful IPv4/IPv6 warm probes before drain;
- 45 acknowledged flow twins;
- proof-complete graceful promotion in 10.860 seconds with one bounded probe
  failure and exclusive address ownership;
- stable recovered-node membership without ownership churn;
- source-wide fail-closed behavior during abrupt Node `Ready=Unknown`;
- proof-complete recovery in 80.428 seconds after the old owner returned; and
- exact resource, address, label, fixture, allocation, and promotion cleanup.

The schema-v1 evidence file was
`.artifacts/phase8-egress-ha-kind.json`, SHA-256
`5b3a6fc6775b7c164dd80651ce7ddc237b37fbffec14a9db63187e0473d4692c`.
The gate also verifies the sealed structured-recipient checkpoint can be
encoded, restored, and independently revalidated.
