# ADR 0118: Prove bilateral zero-leak egress decisions

**Status:** Accepted and implemented for Phase 8.4a

## Context

The first packet of an explicitly managed flow is the dangerous point in an
egress system. A source can observe intent before it has an admitted contract,
or a gateway can receive traffic whose address and gateway selection it cannot
independently justify. Falling back to native routing in either interval leaks
the workload or node source address and defeats deterministic egress identity.

This is not merely theoretical differentiation. Current Cilium documentation
describes a delay for new Pods during which traffic can leave without egress
gateway redirection, and records feature coupling and incompatibilities. Current
OpenShift OVN-Kubernetes documentation records an extra gateway hop, ambiguous
selection when multiple EgressIP objects or addresses match, and failover that
can take seconds or longer. Current Calico documentation says open-source
Calico does not support egress gateways and describes Enterprise/Cloud transit
Pod and CNI requirements. These are bounded observations, not a claim that UNF
already surpasses those products operationally:

- <https://docs.cilium.io/en/latest/network/egress-gateway/egress-gateway/index.html>
- <https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/ovn-kubernetes_network_plugin/configuring-egress-ips-ovn>
- <https://docs.tigera.io/use-cases/egress-gateways>

Phase 8.5 needs one unambiguous behavior contract before fixing the packet ABI.

## Decision

UNF introduces the **Egress Proof Chain**, enabled by default whenever explicit
egress intent selects an identity. It has three inseparable invariants.

1. Admission follows `Native -> Fenced -> Active`. The fence is distributed
   before allocation/contract activation and drops new matching flows. An
   active identity returns to `Fenced` before provider withdrawal and can return
   to `Native` only through an explicit, owner-matched release. No error path
   silently changes an explicitly managed flow back to native egress.
2. The exact original IPv4 or IPv6 TCP/UDP tuple selects a same-family egress
   address and ready/reachable gateway with domain-separated SHA-256 rendezvous
   hashing. Inputs include intent UID and lease epoch. Selection is deterministic
   across source and gateway, distributes flows across multiple candidates, and
   removing a non-selected candidate does not remap the flow.
3. The source issues a versioned flow proof only from an `Active` admission.
   The proof commits the authoritative identity, intent, full contract digest
   and revisions, lease epoch, original tuple digest, chosen address/gateway,
   and decision witness. The selected gateway independently derives the same
   proof from its authenticated admitted contract and authoritative identity
   lookup. Any tuple, gateway, revision, selection, or digest mutation fails
   closed.

The proof is deliberately **not** a bearer credential. Packet-provided proof
bytes never establish workload identity and cannot authorize traffic. Existing
authenticated distribution, exact-Node contract replay, lease ownership, and
gateway identity lookup remain the authority.

SHA-256 rendezvous is the canonical userspace reference algorithm. Phase 8.5
will lower its decision inputs into bounded fixed-width maps/tables; it must not
assume that arbitrary JSON or per-packet SHA-256 belongs in eBPF. Fragmented,
mixed-family, zero-port, and non-TCP/UDP flows fail closed until separately
designed and qualified.

## Consequences

- Explicit intent cannot leak through native routing while state converges or
  withdraws.
- Multiple egress addresses and gateways have one reproducible choice rather
  than implementation-dependent behavior.
- Both ends can explain and audit the same decision without treating a source
  IP, packet metadata, or proof token as identity.
- Lease epoch changes intentionally invalidate prior ownership and selection.
- Phase 8.4a proves reference/control semantics only. It changes no current BPF
  ABI, host routing, live address ownership, packet behavior, or platform claim.
- Live steering/NAT still requires collision handling, reverse state, MTU and
  route validation, bounded provenance, recovery, and independent Kind and
  OpenShift qualification.

## Verification

`make egress-proof-test` checks the tracked decision, required implementation
invariants, ten focused adversarial tests, formatting, and strict Clippy.
