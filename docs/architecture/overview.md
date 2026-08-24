# Architecture overview

## Context

Phase 1 overlays observation on an existing Kubernetes CNI. UNF neither creates
pod interfaces nor owns routing. This makes the initial adoption path reversible.

```text
Kubernetes / OpenShift API
          |
          v
   unf-controller ---- HTTP status/topology/flows/explain/simulate ---- unfctl
          |
   desired state (identity + policy snapshots: epoch + revision)
          |
       internal HTTP polling
          |
          v
      unf-agent ---- Aya ---- TC ingress/egress
                                  |
                           counters + ring buffer
```

The policy compiler is a pure userspace library. Kubernetes types pass through a
conversion boundary before they reach domain policy IR. The kernel sees only
fixed-size numeric state and does no selector or Kubernetes interpretation.

## Phase 1 through 3 data flows

1. kube-rs watches Nodes, Pods, Namespaces, Services, EndpointSlices,
   SecurityPolicies, and NetworkPolicies.
2. Pod metadata becomes provisional network identities. Namespace labels remain
   separate selector metadata, while policy-relevant named-port mappings join the
   canonical identity key so incompatible destinations cannot alias.
3. SecurityPolicies and the supported NetworkPolicy ingress subset compile into
   the same provenance-preserving IR; unsupported compatibility objects are
   rejected without retaining stale compiled state.
4. `unfctl topology` queries a versioned snapshot of Nodes, Pod placement,
   Services, selector-derived intent, and EndpointSlice runtime backends with
   readiness/serving/termination state. `unfctl explain` asks the controller to
   resolve two Pods and evaluate the IR.
   `unfctl policy simulate` compiles a candidate without applying it and compares
   current/proposed decisions over a probe matrix fenced to the reported topology
   revision.
5. The agent loads the Aya object, attaches TC, applies the controller's revisioned
   dual-stack identity snapshot to separate IPv4/IPv6 maps, consumes compact
   events, and exposes health and per-family map metrics.
   Destination-resolved events enter a bounded non-blocking queue, aggregate by
   logical L3/L4 flow, and export in capped batches. Queue pressure drops telemetry
   while forwarding continues.
6. The controller resolves policy selectors to identity tuples and bounded
   IPv4-source tuples; each agent stages both dual-bank maps and atomically
   activates the resulting policy revision with one configuration write.
   Namespace label changes advance this policy revision when selector results can
   change.
7. TC parses direct-header IPv4/IPv6 TCP, UDP, and SCTP, reads the active
   family-neutral identity policy revision, emits actual and shadow provenance,
   and returns `TC_ACT_SHOT` only for a validated actual deny. IPv6 extension
   headers remain fail-open.
8. The controller retains at most 4,096 logical flow keys in memory, enriches
   current identities on query, and feeds the revisioned snapshot into policy
   simulation separately from representative topology probes.

Identity and policy state are distributed to the kernel and consumed directly in
the Phase 2 fast path. Shadow mode remains non-enforcing by construction.

## Dependency rule

Core primitives have no Kubernetes dependency. `unf-api` owns external API
schemas. `unf-policy` may convert API objects but exposes a Kubernetes-independent
IR. Binaries orchestrate these libraries. See [components.md](components.md).
