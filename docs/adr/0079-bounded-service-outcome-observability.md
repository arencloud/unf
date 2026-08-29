# ADR 0079: Service outcomes use one bounded dataplane evidence path

Status: Accepted and implemented for Phase 4.6

## Context

Phase 4.5 translated ClusterIP packets and retained connection provenance, but
operators could not correlate a Service failure or selected backend across the
kernel, agent, controller, history, and CLI. Logs alone are not a durable or
machine-readable contract, and unbounded per-packet labels would make metrics
unsafe.

## Decision

The TC program publishes fixed 96-byte service events through a bounded ring
buffer. ABI v1 records timestamp, ServiceId, optional BackendId, service
revision, client/frontend/backend tuples, protocol, address family, action, and
reason. The accepted action/reason pairs cover forward and reverse translation,
no eligible backend, invalid or missing map state, failed pair insertion,
rewrite failure, and expired or corrupt connection state. Unknown versions,
sizes, protocols, families, action/reason pairs, or nonzero reserved bytes are
rejected in userspace.

Agent metrics remain low-cardinality totals for events, translations, drops,
expirations, and invalid records. Agent-status schema v4 carries those totals
and only the last bounded ServiceId/BackendId/revision/action/reason tuple. The
event is also placed on the existing non-blocking flow-export queue. Queue
pressure therefore uses the established explicit drop accounting and cannot
block forwarding.

Flow-export schema v4 and flow-history snapshot/checkpoint schemas v5/v3 add an
optional service outcome. The logical history key includes service, backend,
revision, action, and reason so a later failure cannot overwrite a successful
translation for the same client/frontend tuple. Policy observations preserve
their previous identity validation. Service observations instead require a complete client/frontend
address pair, TCP or UDP, a nonzero ServiceId/revision/frontend port, an exact
action/reason/verdict relationship, and complete same-family backend provenance
when a BackendId is present. Older history checkpoints remain readable and
default the additive service field to absent.

`GET /v1/services/explain` correlates a stable ServiceId and optional BackendId
with current compiled intent and newest bounded durable outcomes. `unfctl
service-explain` exposes the same contract with optional relative/absolute time
windows and limits. `unfctl flows` identifies service outcomes separately from
policy flows. Absence from retained history is explicitly not proof that no
traffic occurred.

## Verification

`make service-operations-test` includes the complete Phase 4.1–4.5 prerequisite
chain, release eBPF build, kernel verifier and packet execution, strict Clippy,
and state/agent/controller/CLI tests. The privileged packet gate drains the
service ring and requires twelve translation events, one expiry event, one
no-backend drop, and exact ServiceId/revision provenance. Unit tests verify ABI
rejection, agent status, export conversion, controller admission, durable
checkpoint recovery, and the bounded CLI query.

This evidence validates the operations contract and real kernel emission. It
does not claim end-to-end kube-proxy-free cluster Service forwarding; that claim
belongs to Phase 4.7.

## Consequences

Phase 4.6 is independently testable and all Service outcomes share one bounded,
versioned evidence path. Per-Service Prometheus labels are deliberately absent;
operators use status for the most recent tuple and history/explanation for
cardinality-bearing detail. Phase 4.7 can now require the same identifiers and
reasons while exercising lifecycle and recovery in a dedicated Kind cluster.
