# ADR 0040: Direction-aware NetworkPolicy what-if simulation

Status: Accepted and live verified on dual-stack kind

## Context

The read-only simulation API accepted only the native `SecurityPolicy` resource.
NetworkPolicy ingress and egress already share the controller's policy IR and
evaluator, but operators could not inspect a candidate Kubernetes policy without
applying it. The representative topology matrix was also ingress-only, so merely
adding another input type would have produced incorrect egress results.

## Decision

Simulation request schema v4 accepts one manifest whose `kind` is either
`SecurityPolicy` or `NetworkPolicy`. The controller parses and compiles it through
the same resource-specific compiler used for enforcement. Namespace/name identity
drives add or replace semantics within that resource kind. A NetworkPolicy
replacement removes every currently admitted direction for that object from the
proposed in-memory set, then adds all effective directions from the candidate.
Rejected NetworkPolicy objects are recognized as replacements without admitting
their rejected state into the current policy set.

The representative matrix selects destination workloads for ingress and source
workloads for egress. It evaluates every relevant Pod pair, concrete and fallback
TCP/UDP/SCTP port, and each IPv4/IPv6 family shared by the pair. Egress evaluation
receives the concrete destination address, preserving `ipBlock` and exception
semantics. The 10,000-flow bound applies after direction and address-family
expansion.

Response schema v4 reports resource kind, selected source/destination counts, and
direction, address family, and concrete addresses on every topology change.
Retained history is evaluated through its recorded direction. The operation is
strictly read-only: watched objects, compiled stores, revisions, agent snapshots,
and BPF maps are not mutated.

## Verification

Controller tests prove a dual-stack egress NetworkPolicy replacement predicts
IPv4 and IPv6 allow-to-deny changes, uses replace semantics, and leaves the live
compiled object and policy revision unchanged. CLI tests parse both checked-in
resource kinds.

The focused dual-stack Kind egress gate simulates replacing the active named-port
allow with default deny. It requires direction- and address-exact topology
changes, observation-weighted historical denial impact, an unchanged policy
revision, and continued live IPv4/IPv6 forwarding after the request.

## Consequences

Operators can use one command and response contract for native and Kubernetes
policy proposals, including multi-direction NetworkPolicy objects. Dual-stack
matrix expansion can reach the existing safety limit sooner; requests fail
explicitly instead of returning a partial result.

Topology simulation remains Pod-to-Pod. External endpoints may be retained in
history, but entries whose non-selected identity does not resolve to current Pod
topology are still counted as skipped rather than represented synthetically.
