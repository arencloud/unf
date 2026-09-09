# ADR 0158: Bound the attested encryption fabric

**Status:** Accepted and implemented for the Phase 9.1 architecture boundary

## Context

Phase 8 closes UNF's identity-aware egress fabric on independent Kind and
OpenShift gates. Master-prompt §25 next requires WireGuard-based L3 encryption,
including node-to-node and selective policy-required encryption, safe key
rotation, and observability. Section 26 then requires encrypted transport as a
foundation for multi-cluster networking.

Creating one tunnel per workload or policy would multiply interfaces, peers,
routes, handshakes, and state while obscuring which requirement selected a
packet. Conversely, treating a configured peer or recent handshake as proof of
encrypted workload delivery would allow route drift and partial rollout to be
reported as secure. A controller-owned private-key store would also enlarge the
blast radius and violate least authority.

## Decision

Phase 9 uses kernel WireGuard as a versioned L3 transport provider. UNF manages
configuration and evidence in Rust but never implements cryptographic
primitives or exposes cipher selection. Private keys are generated from the OS
CSPRNG through a maintained WireGuard interface, programmed through the kernel
provider, and remain on their owning Node; authenticated Node-UID-bound
publications contain public keys and monotonically versioned metadata only.

Every required path is authorized by a canonical Attested Encryption Path
Contract. It binds both cluster/Node/workload identities, the original traffic
domain, policy and routing inputs, provider capabilities, public-key digests,
key epoch, endpoint, disjoint AllowedIPs, interface/route/fwmark/MTU facts,
deadlines, and all contributing revisions. Both endpoint agents independently
replay it, read back their owned kernel state, and answer a nonce-bound encrypted
challenge. The controller joins evidence but cannot synthesize it. Handshake
recency alone is insufficient.

The Intent-Coalesced Cryptographic Fast Path retains authorization per identity
and destination but shares transport only across an identical trust-domain,
destination-Node, key-epoch, and path-class tuple. Userspace compiles bounded
fixed-width decisions; eBPF applies policy first and selects a transport/epoch
with bounded lookups; kernel WireGuard performs all cryptography. There is no
interface, peer, or userspace forwarding path per workload or policy.

Flow-Stable Epoch Rotation permits exactly two epochs. A prepared epoch becomes
active for new flows only after mutual contract and kernel-path evidence.
Existing admitted flows retain the previous epoch for a bounded drain period,
after which positive flow drain and route absence permit exact retirement.
Missing, stale, conflicting, expired, or revoked required state denies closed
and never falls back to plaintext.

Security policy against the original tuple precedes Service/egress selection
and encryption. Encryption cannot grant connectivity, backend eligibility,
address ownership, or reachability. Fresh primary-CNI installations will default
managed cross-Node Pod paths to Required only after Phase 9 qualifies. Upgrades
stage and prove complete encrypted reachability before an explicit activation;
milestone 9.1 itself changes no packet behavior.

All state uses capability negotiation, independent revisions, inactive staging,
exact readback, last-known-good retention where it cannot cause plaintext
downgrade, rollback, restart repair, and version-scoped cleanup. Performance
claims require committed native-versus-encrypted throughput, latency, CPU,
memory, map-operation, peer-scale, MTU, convergence, and rotation measurements.
Kind and OpenShift qualification remain independent and non-transitive.

## Consequences

- Per-identity authority remains explainable while bounded Node-level transport
  avoids per-policy tunnel and handshake explosion.
- Two-sided authenticated readback plus an encrypted challenge distinguishes
  configured intent from proven path behavior without claiming hardware
  attestation.
- Node-local private keys reduce controller compromise impact, but Node loss
  requires a new key epoch and explicit remote withdrawal/recovery.
- Two-epoch flow stability consumes temporary duplicate peer/interface/route
  state; capacity must be admitted before rotation starts.
- Required encryption prioritizes confidentiality over availability: a missing
  proof drops affected new flows rather than silently using native routing.
- WireGuard's fixed protocol suite is an intentional provider property. Future
  provider or post-quantum work requires a new versioned contract and gate, not
  custom cryptography inside UNF.
- Phase 9.1 creates no CRD, key, interface, route, BPF ABI, packet behavior, or
  platform-support claim.
- Cross-cluster transport, overlapping CIDRs, global services, mTLS,
  post-quantum cryptography, TPM attestation, IPsec/MACsec, L7, Gateway API,
  host/control-plane encryption, and production availability/scale remain
  explicitly excluded.

## References

- WireGuard, [Protocol & Cryptography](https://www.wireguard.com/protocol/)
- WireGuard, [Routing & Network Namespace Integration](https://www.wireguard.com/netns/)
- WireGuard, [Quick Start and kernel interface](https://www.wireguard.com/quickstart/)
