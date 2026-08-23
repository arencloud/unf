# Architecture overview

## Context

Phase 1 overlays observation on an existing Kubernetes CNI. UNF neither creates
pod interfaces nor owns routing. This makes the initial adoption path reversible.

```text
Kubernetes / OpenShift API
          |
          v
   unf-controller ---- HTTP status/explain ---- unfctl
          |
   desired state (identity snapshot: epoch + revision)
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

## Phase 1 data flows

1. kube-rs watches Pods, Namespaces, and SecurityPolicies.
2. Pod metadata becomes provisional network identities.
3. SecurityPolicies compile deterministically into provenance-preserving IR.
4. `unfctl explain` asks the controller to resolve two Pods and evaluate the IR.
5. The agent loads the Aya object, attaches TC, applies the controller's revisioned
   IPv4 identity snapshot, consumes compact events, and exposes health and metrics.

Identity state is now distributed to the kernel as the first Phase 2 slice. Policy
state is not distributed, so observation and userspace shadow explanation remain
non-enforcing.

## Dependency rule

Core primitives have no Kubernetes dependency. `unf-api` owns external API
schemas. `unf-policy` may convert API objects but exposes a Kubernetes-independent
IR. Binaries orchestrate these libraries. See [components.md](components.md).
