# ADR 0128: Lease-fenced gateway address ownership

**Status:** Accepted and implemented for the Phase 8.5 gateway-address slice

## Context

The durable egress control plane allocated addresses and issued gateway desired
state, but production had no native provider that could make those addresses
local on selected gateways. Treating one successful Node as readiness for a
replicated gateway set would allow the controller to publish a contract whose
standby paths had never acquired the lease. Removing addresses immediately on
intent withdrawal would create the opposite race: established source flows
could still target a gateway after its address disappeared, and the allocator
could reuse that address before every source had installed its fence.

Linux address updates are individually atomic, not a distributed transaction.
Controller leadership, elapsed grace periods, and last-writer-wins state do not
prove either complete acquisition or safe release.

## Decision

The controller issues a strict schema-v1 gateway-address projection to each
Pod-bound authenticated agent. The projection binds the controller epoch,
gateway-registry revision, exact Node name and UID, every assigned desired
revision, owner, provider, allocation revision, lease epoch, action, address,
and selected Node set under a domain-separated SHA-256 digest. The agent admits
that envelope against its independently fetched authoritative Node UID before
host mutation.

Each selected gateway owns the projected IPv4 and IPv6 addresses as `/32` and
`/128` host prefixes on the dedicated `unf-egress0` dummy interface. Its alias
is versioned and bound to the Node UID. The native provider validates the whole
host for duplicate address ownership before mutation, refuses a same-named
foreign interface or changed alias/type/MTU, adds only missing addresses, rolls
back a partial add, and independently reads back the exact managed set. IPv6
link-local kernel state is not mistaken for an egress address.

The resulting acknowledgement binds the projection and kernel interface index,
MTU, complete owned-address set, applied Ensure revisions, and quarantined
Withdraw revisions. The controller synthesizes provider `Ready` only after
current exact acknowledgements from every selected Node. A single Node, stale
Pod UID, replacement Node UID, partial address set, mutated digest, or stale
projection cannot advance readiness.

Withdrawal is deliberately two-phase. This slice classifies Withdraw leases as
quarantined and keeps their address ownership plus allocator fence. It never
synthesizes `Withdrawn`, never releases the lease, and never relies on a timer.
The exact release primitive exists but can be invoked only by a future explicit
release authority after every affected source proves destination-preserving
fence installation and reachability has been withdrawn.

## Consequences

Gateway address acquisition is live, dual-stack, collision-safe, restart
idempotent, independently read back, and all-Node quorum-gated. Assigning the
same address to multiple selected gateways prepares safe anycast-style HA
without itself advertising a route. Allocation, local ownership, reachability,
source activation, and NAT remain separate authorities.

Fail-closed quarantine may intentionally retain an address indefinitely when
source-fence or reachability proof is unavailable. This consumes capacity but
cannot cause unsafe reuse; availability never silently wins over correctness.
The next slice must add explicit source-fence/reachability withdrawal evidence
before exercising release, then implement collision-safe TCP/UDP SNAT and
reverse state. This ADR makes no NAT, advertisement, traffic, failover, Kind,
or OpenShift claim.

`make egress-gateway-address-test` inherits all path-activation checks and adds
projection mutation and Node-UID replacement tests, Ensure/quarantine evidence,
controller all-Node quorum, plan validation, strict Clippy, and an isolated
real-kernel namespace test for dual-stack application, readback, restart,
foreign collision refusal, exact release, and idempotent absence.
