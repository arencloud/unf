# ADR 0094: Model LoadBalancer intent in service schema v3

**Status:** Accepted and implemented for Phase 6.2 (2026-08-31)

## Context

Phase 6 needs a provider-neutral boundary between Kubernetes Service intent and
later VIP allocation, reachability, host state, and packet translation. Reusing
a ClusterIP or NodePort record as a VIP would erase ownership and readiness
boundaries. Sending a new field without an explicit schema transition would
also let an older consumer acknowledge state it did not understand.

Kubernetes adds further ambiguity: classless and foreign-class Services belong
to another implementation; `loadBalancerIP` is only a requested address, not a
durable lease; and source ranges, family policy, NodePort allocation, and Local
health behavior must stay attached to the exact Service-port/backend intent.

## Decision

Service snapshot schema v3 adds one optional `ServiceLoadBalancer` record to a
Service. It contains:

- the exact `network.unf.io/load-balancer` class;
- one or two typed address families plus the Kubernetes family policy;
- requested IPs kept distinct from future allocated leases;
- `Cluster` or `Local` external traffic policy;
- canonical bounded IPv4/IPv6 source prefixes;
- `allocateLoadBalancerNodePorts` and optional health-check NodePort intent; and
- one exact family/port/protocol/name/app-protocol frontend per admitted
  ClusterIP Service port with identical backend references.

The compiler canonicalizes all sets, enforces fixed global and per-Service
bounds, rejects duplicate or ClusterIP-colliding requested addresses, rejects
inexact links and unsupported SCTP/affinity/internal-policy/topology semantics,
and retains the controller's last valid source and compiled revision on error.
Classless and foreign-class LoadBalancer Services remain foreign: UNF does not
compile their VIP intent or adopt their status.

Schema-v3 producers can project an exact schema-v2 view by removing only
LoadBalancer intent, and an exact schema-v1 view by also removing NodePort
intent. Readers migrate valid v1/v2 state but reject either older schema when it
is disguised with newer intent. Existing ClusterIP and NodePort lowerers reject
any v3 LoadBalancer record, so compilation cannot be mistaken for allocation,
advertisement, host adoption, or packet convergence.

## Consequences

- Address allocation can consume deterministic requested intent without
  treating a request or Kubernetes status value as ownership.
- Provider, dataplane, and status transactions remain absent and cannot be
  acknowledged through the existing service maps.
- The v2 projection gives the following compatibility milestone an explicit
  downgrade boundary rather than an implicit unknown-field behavior.
- Direct VIP delivery remains independent of traffic NodePort allocation.
- BGP/cloud providers, status/finalizer writes, allocation persistence, host
  maps, health sockets, and packet support remain later milestones.

## Verification

`make loadbalancer-ir-test` verifies schema v3 and v1/v2 migration/projection,
dual-stack TCP/UDP frontend and backend linkage, class/family/policy/requested-IP
and source-range validation, collision and unsupported-semantics rejection,
NodePort-allocation preservation, foreign/classless ownership, retained-last-
valid Kubernetes behavior, explicit lowerer rejection, focused compatibility
tests, and strict Clippy. The full workspace test suite passes unchanged.
