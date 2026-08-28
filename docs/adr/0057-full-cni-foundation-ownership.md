# ADR 0057: Full-CNI entry uses local transactions and explicit ownership

Status: Accepted for the full-CNI foundation

## Context

Phase 3 is Verified, satisfying the master prompt's prerequisite for beginning
full-CNI work. The existing UNF deployment is an overlay: another CNI creates
Pod interfaces and owns routing while UNF observes and enforces policy. Replacing
that CNI implicitly would make rollback unsafe and would mix persistent network
ownership into a latency-sensitive executable.

The current upstream [CNI specification](https://www.cni.dev/docs/spec/) is
version 1.1.0. It defines ADD, DEL, CHECK, VERSION, STATUS, and GC behavior,
requires JSON protocol output, permits concurrent operations for different
attachments, requires repeated DEL to succeed when resources are absent, and
defines `(CNI_CONTAINERID, CNI_IFNAME)` as the attachment identity.

## Decision

### Adoption and ownership

UNF retains two explicit deployment modes:

- `overlay` is the existing default. UNF owns no Pod links, addresses, or routes.
- `primary` is opt-in full-CNI ownership. It starts only on an isolated Kind
  fixture and must never be installed by the existing Kubernetes or OpenShift
  overlays.

There is no in-place takeover of a running Pod. A node changes primary CNI only
after cordon, drain, empty-state verification, configuration switch, and fresh
Pod creation. Rollback uses the reverse sequence. OpenShift cl02 is not a CNI
replacement target until the Kind lifecycle is complete and an OpenShift-specific
Network Operator/MachineConfig design is accepted.

In `primary` mode, ownership is exact:

| Resource | Owner |
|---|---|
| CNI stdin/environment parsing and one attachment's namespace operations | `unf-cni` |
| Durable attachment transaction, allocation lease, and recovery state | local `unf-agent` |
| Host veth peer, endpoint routes, UNF sysctls, and BPF attachment | local `unf-agent` reconciler, with bounded link application requested by `unf-cni` |
| Pool and node-block desired state | `unf-controller` |
| Kubernetes watches, policy, services, topology, and route distribution | long-running components, never `unf-cni` |

Every host object uses an exact UNF name/alias or protocol identity. Cleanup and
uninstall refuse unrecognized state and never scan-delete arbitrary links,
routes, files, or CNI configurations.

### CNI executable boundary

`unf-cni` supports CNI 1.0.0 and 1.1.0. Configuration is bounded at 1 MiB and
initially accepts only `mode: primary`, `dataplane: veth`, `ipam.type: unf`, an
absolute local agent socket, and MTU values valid for dual stack. VERSION is
functional immediately. ADD and CHECK return a structured retry error, and
STATUS reports unavailable, until the local agent transaction API exists and
completed IPAM/link lifecycle operations are connected through it. DEL and GC
are idempotent no-ops while this binary cannot create resources. This prevents a
partially implemented plugin from returning false success.

The executable never calls Kubernetes, compiles policy, manages services, runs a
routing protocol, or aggregates telemetry. Structured CNI results are the only
stdout content; diagnostics belong on stderr. Each execution has bounded input,
timeouts, response size, and a single local Unix-socket round trip sequence.

### Agent transaction and state contract

The next slice introduces a root-authenticated Unix socket at
`/run/unf/cni.sock`. It uses peer credentials, a bounded versioned JSON protocol,
and this state machine keyed by network name, container ID, and interface name:

```text
absent -> preparing -> ready -> deleting -> absent
                 \-> aborting -> absent
```

ADD prepares an allocation and deterministic host-link identity, applies the
veth/netns plan, then commits only after read-back validation. A failure after
prepare rolls back link and allocation state before returning. CHECK compares
the supplied `prevResult`, durable transaction, allocation, link, addresses,
routes, MTU, and agent readiness. DEL is repeatable, tolerates a missing network
namespace or link, and releases the lease only after owned host state is absent.
GC reconciles only exact stale attachment keys and is never a substitute for DEL.

Agent unavailability makes ADD/CHECK fail with a retryable error. Existing Ready
attachments retain last-known-good host and BPF state. DEL may remove known local
link state but must not report a critical IPAM release complete until the durable
agent transaction records it.

### IPAM, links, routing, and MTU boundaries

IPAM is a provider trait rather than routing policy. The first provider uses
controller-assigned dual-stack node blocks and agent-local durable leases.
Allocation and release are serialized per node, collision checked across both
families, recoverable after restart, and bounded under exhaustion. Static and
delegated providers remain later implementations, not a generic plugin system.

Portable veth is the first and default link type. Netkit remains rejected until
a separate comparison ADR and kernel/platform matrix exist. Initial routing is
native, per-endpoint L3 with explicit IPv4 and IPv6 routes; overlay, BGP, hybrid,
and multi-cluster modes remain behind a routing-provider interface. Policy does
not depend on the chosen routing provider.

MTU is one versioned node input. Native mode derives workload MTU from the
underlay with zero encapsulation overhead; future encapsulating providers must
declare their overhead. Dual-stack configuration rejects MTU below 1280. ADD and
CHECK use the same recorded value, and rollback restores only UNF-owned state.

## Alternatives

Putting allocation and durable recovery entirely in the executable would avoid
the local socket but would duplicate locking, persistence, observability, and
upgrade logic in every short-lived invocation. Asking the controller or
Kubernetes API from ADD would make Pod startup depend on remote control-plane
latency and availability. Chaining behind the existing primary plugin would be
useful for policy but would not exercise full-CNI ownership. Netkit-first would
exclude qualified RHCOS 5.14 and other kernels without its required support.

## Consequences

Milestone 6 is In progress. Architecture/ownership item 6.1 is Verified, and
6.2 begins with a compiling, tested protocol boundary that cannot create Pod
networking yet. IPAM, veth lifecycle, routing/MTU, node-to-node networking, CNI
installation, and cluster qualification remain explicit later slices.

No production or OpenShift full-CNI support claim exists. The existing overlay
deployment and its Phase 3 behavior are unchanged.
