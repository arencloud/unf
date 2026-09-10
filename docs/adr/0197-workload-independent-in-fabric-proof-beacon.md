# ADR 0197: Workload-Independent In-Fabric Proof Beacon

- Status: Accepted and implemented for Phase 9.6d
- Date: 2026-09-10

## Context

An encrypted path challenge aimed at an ordinary Pod inherits Pod readiness,
rescheduling, policy, Service, and application behavior. A separate probe CIDR
requires new routing authority and can accidentally prove a tunnel different
from the Pod CIDR selected by the encryption contract. Reusing a gateway address
can collide with CNI link ownership.

## Decision

Phase 9.6d adds the **Workload-Independent In-Fabric Proof Beacon**:

- each UNF IPv4 Node block already excludes network, gateway, and block-end
  addresses; its block-end becomes the beacon and is installed as a `/32`;
- each UNF IPv6 Node block already begins workload allocation at `network + 2`;
  its network address becomes the beacon and is installed as a `/128`;
- the host prefixes create no connected pool route, remain unique because Node
  Pod CIDRs cannot overlap, and can never be returned by UNF IPAM;
- WireGuard provider schema v2 derives the addresses from the exact local Pod
  CIDRs, includes both inputs and results in its plan digest, installs them on
  the epoch interface, and includes exact address readback in its stable kernel
  configuration digest;
- capability negotiation requires exact proof-beacon support, preventing an
  adjacent provider from silently ignoring the new authority; and
- route validation admits only the precise Linux kernel local/connected routes
  caused by those addresses. Any other route on the owned interface remains
  foreign state.

The destination beacon is inside the same full Pod CIDR `AllowedIPs` and route
that real managed traffic uses. It therefore proves the intended encrypted
route without a per-workload tunnel, a userspace forwarding data path, a probe
Pod, or additional routable address space.

## Consequences

The beacons are infrastructure identities, never workload identities and never
policy permission. They exist only on an inactive or active UNF-owned WireGuard
epoch interface and disappear with exact interface cleanup. A nonce protocol
must still prove freshness, response direction, and counter movement before a
beacon can contribute activation evidence; that executor is the next slice.

## Verification

`make encryption-proof-beacon-test` inherits every prior encryption gate, proves
IPAM exclusion through exhaustion, checks canonical derivation and mutation
rejection, runs strict Clippy, exercises exact create/readback/replay/rollback/
cleanup against the real Linux provider, and sends both workload-like and beacon
IPv4/IPv6 traffic through full Pod CIDR `AllowedIPs` while underlay capture sees
only WireGuard UDP ciphertext.
