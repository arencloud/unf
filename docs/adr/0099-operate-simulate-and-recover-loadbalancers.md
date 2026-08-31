# ADR 0099: Operate, simulate, and recover LoadBalancers

**Status:** Accepted and implemented for Phase 6.7 (2026-08-31)

## Context

Milestones 6.5 and 6.6 made Cluster and Local VIP traffic functional, but an
operator still needed several unrelated views to distinguish desired
allocation, Node reachability, active translation, source-range denial, local
health, or recovery failure. NodePort already had bounded status, history,
explanation, and simulation patterns. LoadBalancer operations must extend those
patterns without per-Service metric labels, mutating live state during a query,
or falsely treating allocation, advertisement, and dataplane readiness as one
revision.

## Decision

- The agent exposes fixed-name, label-free metrics for desired/applied
  reachability and allocation revisions, total/Cluster/Local frontend counts,
  source prefixes, health listeners and ready listeners, reconciliation errors,
  Cluster/Local translations, no-backend drops, and source-range drops.
- Agent status keeps schema v6 and adds defaulted bounded fields carrying the
  same frontend, health, and event totals. Admission requires Cluster plus Local
  counts to equal the active total, source-prefix capacity to remain bounded,
  ready health checks not to exceed owned listeners, and nonzero active counts
  to reference an applied revision.
- Flow export schema v5 and history snapshot/checkpoint schemas v6/v5 already
  admitted the Phase 6.6 LoadBalancer frontend kinds. Durable history now has
  explicit restart evidence for Local outcomes. Existing 4,096 runtime and
  1,024 durable-entry bounds remain unchanged.
- Service explanation includes the exact lease, pool UID, provider,
  allocation/reachability revisions, reachable Nodes, and currently converged
  Nodes for LoadBalancer intent. Bounded retained outcomes remain filterable by
  `load_balancer_cluster` or `load_balancer_local`.
- `GET /v1/services/loadbalancer/simulate` and `unfctl
  load-balancer-simulate` accept an exact receiving Node, VIP, client source,
  Service port, and TCP/UDP protocol. They evaluate current VIP ownership,
  family, frontend linkage, source ranges, traffic policy, endpoint lifecycle,
  and Local placement and return `translate`, `drop_no_backend`, or
  `drop_source_range` with allocation/provider/revision provenance. No
  revision, checkpoint, map, connection, history, or provider state changes.
- The immediately adjacent Phase 6.6/6.7 revisions retain the same component
  compatibility tuple and persistent ABI v6. New status fields are defaulted
  for the prior reader and ignored as additive fields by it; both revisions
  already share Cluster/Local LoadBalancer event kinds. Unsupported tuple or
  provider ownership changes still fail closed.
- Controller/provider restart reconstructs exact leases and reachability from
  the durable owner/provider tuple. Agent replacement reconstructs active VIP
  banks, runtime source tries, health intent, and bounded operational counts
  before attachment. A changed provider identity is rejected rather than
  adopted.

## Consequences

An operator can distinguish allocation, reachability, dataplane, source policy,
and Node-local health from stable metrics, status, history, explanation, and
simulation. Cardinality remains independent of Service count. Queries cannot
become a control-plane mutation channel, and recovery cannot silently adopt a
foreign provider.

The local gate proves software and real-kernel recovery boundaries but does not
claim externally routed VIP lifecycle, multi-Node outage behavior, or a
platform rollback. Those are deliberately retained for the isolated Kind and
OpenShift milestones 6.8 and 6.9.

## Verification

`make loadbalancer-operations-test` inherits every Phase 6.1–6.6 gate, including
release-object kernel verification and Cluster/Local/NodePort/ClusterIP packet
execution. It then verifies fixed metric exposition and status invariants,
durable LoadBalancer history, provenance-rich explanation, exact read-only
allow/source-deny/no-backend simulation, CLI query construction, durable
controller/provider replay and foreign-provider rejection, additive adjacent
compatibility, agent map/source-trie replacement recovery, deployment renders,
and strict Clippy.
