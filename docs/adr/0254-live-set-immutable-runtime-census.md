# ADR 0254: Live-Set Immutable Runtime Census

## Status

Accepted and implemented for Phase 9.9 qualification

## Context

The first cl02 run of the ADR 0253 tuple stopped at the immutable-runtime
preflight. Kubernetes retained terminated `Error` and `ContainerStatusUnknown`
Pods from the earlier controller memory-pressure incident. The gate counted
every labelled Pod object and therefore rejected thirteen historical controller
records plus the one healthy live controller as a non-unique runtime.

No baseline migration or fixture creation had occurred. All five exact agent
images and the one exact controller image were Ready with zero restarts.

## Decision

The **Live-Set Immutable Runtime Census** admits only Pod objects that:

- have no deletion timestamp;
- are in Kubernetes phase `Running`;
- carry the exact UNF agent or controller label; and
- expose a Ready, zero-restart component container with the release-record
  digest.

The census must still contain exactly five agents and one controller. Historical
terminated objects remain available for diagnostics but cannot impersonate live
runtime cardinality. Version endpoints, source revision, schema/ABI coordinates,
rollout status, and agent convergence remain independently checked before this
census.

## Consequences

- Real duplicate live controllers, non-Ready containers, restarts, wrong
  digests, or cardinality drift still fail before migration.
- Terminated eviction evidence no longer requires destructive manual deletion
  to qualify a recovered cluster.
- The full OpenShift gate must be rerun from its beginning; this correction by
  itself makes no Phase 9.9 platform claim.
