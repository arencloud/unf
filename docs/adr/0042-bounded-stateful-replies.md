# ADR 0042: Bounded revision-scoped reply state

Status: Accepted and live verified on dual-stack Kind and OpenShift

## Context

Kubernetes NetworkPolicy evaluates ingress and egress independently, but reply
traffic for an allowed connection is implicitly allowed. UNF previously applied
the two directional decisions independently to every packet. A source Pod that
was ingress-isolated could therefore drop the response to a connection that the
same Pod had successfully initiated.

The persistent eleven-map policy ABI is last-known-good desired state. Runtime
connection state has different ownership and expiry requirements and must not
make policy recovery depend on stale flows.

## Decision

The TC program owns a 65,536-entry LRU `CONNECTIONS` map keyed by the complete
IPv4 or IPv6 address and transport tuple. A normally allowed initial TCP SYN, or
an allowed UDP/SCTP packet, records the forward tuple. If normal policy
evaluation denies the reverse tuple, a current entry changes that packet to
`AllowEstablished` provenance while retaining the denied direction and active
policy revision in telemetry.

State is scoped to the active policy revision and uses bounded idle windows:
five minutes for TCP, 30 seconds for UDP, and 60 seconds for SCTP. A policy
revision change therefore invalidates old state immediately. This is a deliberate
fail-closed choice within Kubernetes' implementation-defined behavior for policy
changes affecting existing connections.

`CONNECTIONS` is runtime-only. It is neither pinned nor part of the persistent
policy ABI. Replacing the eBPF program resets established state; the eleven
identity/policy maps and their offline-recovery contract are unchanged.

## Verification

Shared tests cover stable tuple layout and reversal, initial-SYN admission,
UDP/SCTP admission, timeout boundaries, and revision invalidation. The workspace
lint/test/eBPF gates pass, and a rebuilt two-node Kind deployment proves kernel
verifier acceptance.

The upstream-aligned ingress matrix now runs the formerly excluded
same-Namespace client under namespace-wide ingress default deny plus a
target-specific allow containing both empty Pod and Namespace selectors. Direct
TCP requests and replies pass over IPv4 and IPv6, and agent telemetry must expose
`AllowEstablished` reason code 6 for both families at the converged revision.

The dual-stack OpenShift gate additionally proves cross-worker runtime state and
the OVN same-node compatibility fallback recorded in ADR 0043. The fallback is
needed because a same-node OVN path can bypass the TC observation point that
would otherwise record the initial packet.

## Consequences

UNF now implements the Kubernetes L4 reply-traffic contract for its supported
TCP, UDP, and SCTP protocols without expanding persistent recovery state. It
does not claim generic conntrack `RELATED` behavior, ICMP error association,
NAT tuple reconstruction, non-initial fragment tracking, or survival across an
eBPF program replacement.
