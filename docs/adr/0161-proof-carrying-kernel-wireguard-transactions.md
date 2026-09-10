# ADR 0161: Proof-carrying kernel WireGuard transactions

**Status:** Accepted and implemented for Phase 9.4

## Context

An encryption plan is not evidence that Linux accepted the same configuration.
WireGuard device state, routes, link properties, and live counters arrive through
different kernel APIs and can change independently. A crash can also occur after
creating an interface but before installing every peer or route. Blind replay or
name-based cleanup could then overwrite or remove state owned by an operator.

Scaling adds a second trap. Pairwise overlap checks over 65,536 `AllowedIPs`, or
rescanning the complete route table once per desired prefix, would turn recovery
into quadratic work exactly when the Node is already under pressure.

## Decision

`unf-encryption` owns a Linux `WireGuard` provider implemented with maintained,
typed Rust generic-netlink and rtnetlink APIs. The provider accepts a canonical,
bounded plan and Node-local private-key reference, creates one version-owned
interface per epoch, replaces the complete peer set, installs disjoint IPv4 and
IPv6 routes in an isolated table, and independently reads everything back before
returning success. No shell command output is parsed and UNF implements no
cryptography.

The provider introduces a **Proof-Carrying Kernel Transaction**. A secret-free,
domain-separated checkpoint binds the transaction revision, complete desired
plan, optional before-configuration digest, phase, and independently observed
readback digest. Recovery is a total decision: apply an absent prepared stage,
commit an exact observed stage, recognize positively absent rollback, or refuse
unknown state. A verified prepared checkpoint can authorize rollback of a fresh
stage, but cleanup still requires the exact versioned link alias and positive
link/route absence. Same-name or same-route-key foreign state is never adopted.

Configuration and observation have separate digests. The stable configuration
digest covers interface identity/index, owner alias, MTU, link state, public key,
listen port, fwmark, complete peer endpoints/keepalives/`AllowedIPs`, exact
proof-beacon addresses, and exact routes. The observation digest additionally covers handshake time and byte
counters, so traffic cannot create false configuration drift while operational
evidence remains lossless.

An inactive stage is administratively up but unreachable from workload traffic:
its routes live only in its isolated table and milestone 9.5 has not selected its
epoch bank. This is necessary because Linux cannot reliably stage dual-stack
device routes on a down WireGuard interface, and a down interface could not
perform milestone 9.6's pre-activation encrypted challenge. Activation authority
therefore belongs to the independently committed fast-path bank, not the link's
`UP` bit.

The safe MTU is derived from the complete bounded underlay observation set. The
minimum candidate records its limiting peer, address family, underlay MTU, and
encapsulation overhead. IPv4 subtracts 60 bytes and IPv6 subtracts 80 bytes; the
common result must remain at least 1280. Kernel route readback preserves Linux's
actual family semantics: IPv4 device routes use link scope while IPv6 routes use
universe scope. The one unavoidable kernel-generated IPv6 multicast route is
recognized by its exact prefix, table, protocol, and scope; every other
unexpected route pointing at the owned interface is refused.

Capacity and conflict validation are bounded before mutation. Canonical
`AllowedIPs` are sorted and adjacent-overlap checked in `O(P log P)` rather than
pairwise `O(P²)`. Kernel routes are indexed once by `(prefix, table)` and desired
routes are looked up in `O((R + P) log R)`, with a hard readback bound. This keeps
restart cost predictable without weakening exact ownership.

Private keys are absent from the plan, transaction, snapshot, error, and debug
models. A local key is public-key checked immediately before use. The provider
zeroizes its direct private-key copy after the netlink request and zeroizes any
private or preshared key returned by kernel readback. The typed netlink library
may make transient serialization copies that it does not expose for explicit
zeroization; those buffers are never logged, checkpointed, or returned. Removing
that dependency limitation requires an independently reviewed zeroizing encoder,
not a false security claim.

## Evidence

`make encryption-kernel-provider-test` runs the earlier Phase 9 gates, static
contract checks, 32 `unf-encryption` tests (31 ordinary plus one separately
ignored privileged test), and strict all-target/all-feature Clippy. Tests cover
canonical plans, secret separation, safe dual-stack MTU derivation, capacity,
overlapping route refusal, stable/live digests, mutation, adjacent provider
negotiation, and total transaction recovery.

`make encryption-kernel-provider-live-test` additionally runs against the host
Linux kernel with `CAP_NET_ADMIN`. It injects failure after generic-netlink
device configuration and proves rollback absence, preserves both a deliberately
foreign same-name WireGuard interface and a foreign planned-route key, stages
and reads back exact dual-stack peers/routes/MTU/key metadata, replays
idempotently, reconstructs prepared
rollback, deletes exact owned state, and proves repeated cleanup is absent.

The kernel API contract is documented by the
[Linux WireGuard generic-netlink specification](https://cdn.kernel.org/doc/html/latest/netlink/specs/wireguard.html).
The typed provider uses `netlink-packet-wireguard` 0.5, `genetlink` 0.3, and
`rtnetlink` 0.23. This host-kernel evidence is implementation evidence only; it
does not claim Kind or OpenShift encrypted packet qualification.

## Consequences

- Kernel success now means exact independent readback, not a successful write
  acknowledgement.
- A crash leaves a deterministic, secret-free recovery decision and never
  authorizes adoption or deletion by interface name alone.
- Staging can support future two-ended path proof without allowing workload
  traffic before the fast-path activation bank commits.
- Prefix and route reconciliation remain predictable at the declared bounds.
- Packet steering, mutual encrypted challenge evidence, operations/performance,
  Kind, and OpenShift qualification remain milestones 9.5 through 9.9.
