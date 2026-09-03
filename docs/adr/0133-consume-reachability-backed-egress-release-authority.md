# ADR 0133: Consume reachability-backed egress release authority

**Status:** Accepted and implemented for the Phase 8.5 final-release slice

## Context

ADRs 0130–0132 provide a durable retirement manifest plus authenticated source
fences and lease-specific zero-flow gateway drains. Address reuse must also
wait for external reachability withdrawal and exact removal of the address
from every selected gateway host. Treating a provider acknowledgement or a
controller decision as host readback would leave a race in which an address
could be reallocated while an old Node still owned it.

The first concrete reachability provider is intentionally narrow. A `static`
provider means that UNF owns no mutable per-address advertisement; the operator
has explicitly provisioned the surrounding reachability. Other provider names
receive no inferred acknowledgement and remain fenced until their own adapter
is implemented.

## Decision

The controller emits revision-, provider-, allocation-, owner-, address-, and
lease-bound Ready/Withdrawn acknowledgements only for explicitly selected
`static` providers. Withdrawn evidence is retained in the durable gateway
checkpoint and participates in the same strict replay validation as every
future provider.

Whenever source and gateway evidence arrives, the controller reconstructs the
exact schema-v1 Proof of Safe Forgetting from the retained manifest, complete
source union, complete gateway union, current controller epoch, and exact
reachability withdrawal. Incomplete or mismatched inputs produce no authority.

Gateway-address distribution advances explicitly to schema v2. Its digest now
binds the sorted desired revisions whose complete proof authorizes host
release. An agent may only transition from the previously exact full address
set to a monotonic subset under that projection. The owned dummy interface is
read back before mutation; partial removal is rolled back, exact replay is
idempotent, and the resulting acknowledgement separately identifies applied,
quarantined, and released revisions. Empty retained sets remain as a
Node-UID-owned, address-free interface until ordinary cleanup.

The controller accepts `Withdrawn` gateway-host state only after every exact
selected Node has acknowledged the current release projection and kernel
readback excludes every address of the lease. It then consumes the previously
assembled authority through one cloned control-plane transaction. Gateway
ownership, allocation, and retirement manifest are committed together, with a
new gateway revision; runtime evidence is removed only after success.

## Consequences

There is no interval in which the allocator may reuse an address before every
old gateway has positively removed it. Missing Nodes, partial host quorums,
foreign providers, missing evidence, stale Pods, controller restart, kernel
mutation, and removal failure retain quarantine. Multiple independent leases
on the same gateway are reduced by exact subset, so one retirement does not
interrupt the others.

Static reachability is a development/provider contract, not a claim that UNF
has configured upstream routing. BGP, ECMP, BFD, graceful restart, and cloud or
OpenShift advertisement adapters remain milestone 8.8 work.

`make egress-release-authority-test` inherits all Phase 8.5 gates and adds
schema-v2 projection/acknowledgement tests, current-epoch authority assembly,
provider withdrawal, atomic final consumption, and privileged real-kernel
subset/removal/readback evidence under strict Clippy.
