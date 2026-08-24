# ADR 0011: Versioned topology snapshots

## Status

Accepted and live verified for topology schema v3.

## Context

Policy simulation and future digital-twin queries need a stable description of
the cluster relationships used at evaluation time. Pod-only controller state did
not expose workload placement, Nodes, Services, or an independent revision that
operators could use to correlate results. Kubernetes resource versions are
object-local and include metadata/status churn that is not meaningful to this
domain.

## Decision

The controller watches Nodes, Services, and EndpointSlices in addition to Pods and
publishes `GET /v1/topology`. Schema v3 contains:

- normalized Node name, readiness, and labels;
- each Pod workload's identity, labels, separate IPv4/IPv6 addresses, and node
  placement;
- Service type, cluster IPs, selector, ports, and selected workload references;
- EndpointSlice-derived runtime backends with slice/address provenance, resolved
  Pod target, Node/zone, ports, and ready/serving/terminating conditions;
- controller process epoch, topology revision, and identity revision.

The topology revision advances only when the normalized Pod, Node, Service, or
EndpointSlice model changes. Service and EndpointSlice mutations advance both
service and topology revisions. Topology-only changes do not advance policy
revision, and metadata/resource-version-only updates do not create churn.
All topology mutation and simulation capture uses the controller state fence, so
the topology revision in a simulation response identifies the exact relationship
snapshot used for its Pod matrix.

Service `selected_workloads` remains selector intent; an empty selector selects no
workloads. The separate `backends` list is runtime discovery state joined by the
standard `kubernetes.io/service-name` label. Missing EndpointSlice readiness is
interpreted as ready for Kubernetes compatibility, missing serving follows ready,
and missing terminating is false. Pod `targetRef` values become workload
references even for selectorless Services. Schema v1 was the selector-intent-only
contract.

`unfctl topology` renders the snapshot as a table or preserves the schema as JSON
or YAML. The kind verifier creates and deletes a temporary selector Service,
creates a selectorless Service plus a manual EndpointSlice, requires not-ready →
ready → deleted backend transitions and monotonic topology revisions, and proves
the policy revision remains unchanged.

## Consequences

Operators and simulation clients now have a deterministic, queryable topology
fence without introducing a custom query language. Simulation can attribute an
affected selectorless Service through a ready Pod backend. The snapshot is still
in-memory/current-state only: EndpointSlice conditions are Kubernetes-reported
state, not active health probes. Topology history, pagination, filtering, routing
relationships, and durable storage require later schema or endpoint additions.

Schema v3 is the dual-stack extension of schema v2; all Node, Service, and
EndpointSlice semantics are unchanged.
