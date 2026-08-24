# ADR 0011: Versioned topology snapshots

## Status

Accepted and implemented for topology schema v1.

## Context

Policy simulation and future digital-twin queries need a stable description of
the cluster relationships used at evaluation time. Pod-only controller state did
not expose workload placement, Nodes, Services, or an independent revision that
operators could use to correlate results. Kubernetes resource versions are
object-local and include metadata/status churn that is not meaningful to this
domain.

## Decision

The controller watches Nodes and Services in addition to Pods and publishes
`GET /v1/topology`. Schema v1 contains:

- normalized Node name, readiness, and labels;
- each Pod workload's identity, labels, addresses, and node placement;
- Service type, cluster IPs, selector, ports, and selected workload references;
- controller process epoch, topology revision, and identity revision.

The topology revision advances only when the normalized Pod, Node, or Service
model changes. Service mutations advance both service and topology revisions.
Topology-only Pod placement and Service changes do not advance policy revision.
All topology mutation and simulation capture uses the controller state fence, so
the topology revision in a simulation response identifies the exact relationship
snapshot used for its Pod matrix.

Service `selected_workloads` represents selector intent. An empty selector
selects no workloads. Schema v1 does not claim that selected Pods are ready
runtime backends because EndpointSlice state is not yet consumed.

`unfctl topology` renders the snapshot as a table or preserves the schema as JSON
or YAML. The kind verifier creates and deletes a temporary selector Service,
requires monotonic topology revisions and correct membership, and proves the
policy revision remains unchanged.

## Consequences

Operators and simulation clients now have a deterministic, queryable topology
fence without introducing a custom query language. The snapshot is still
in-memory/current-state only. EndpointSlice readiness, topology history,
pagination, filtering, routing relationships, and durable storage require later
schema or endpoint additions.
