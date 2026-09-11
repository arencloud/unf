# ADR 0214: Causal Pre-Attachment Fleet Barrier

- Status: Accepted and implemented for Phase 9.9
- Date: 2026-09-11

## Context

The first cl02 rollout attempt correctly stopped after one Phase 9 agent did
not become Ready. It exposed an adjacent-upgrade ordering gap: a freshly opened
encryption map island is structurally valid but contains no committed
generation. Startup treated “no recovered generation needs revalidation” as
permission to install the new twelve-stage tail-call graph. On a mixed-version
fleet, the other agents cannot yet contribute Phase 9 key and path facts, so
the first agent can temporarily expose a fail-closed encryption finalizer before
the fleet has produced even its explicit Native generation.

Readiness cannot solve this after attachment: the transition itself may affect
the management traffic needed to complete the first generation. Treating an
empty map as Native inside eBPF would avoid that cycle but would create a silent
plaintext fallback whenever Required authority was lost.

## Decision

An agent connected to a controller now distinguishes a quiescent empty island
from an active proof-carrying generation. It may open the new maps, serve its
health/version/status API, generate Node-local keys, and exchange authenticated
fleet facts, but it cannot populate the shared tail-call graph, replace a TC
attachment, set `bpf_loaded`, or become Ready until a complete generation has
committed locally. Existing persistent TC state remains the packet authority
during that interval.

The guarded OpenShift deployment recognizes this deliberate staging state. It
replaces agents one Node at a time, requires the new digest and live API plus
host/API Service continuity, then waits for all five new members to cross the
barrier and converge before qualification. The bounded startup window is 30
minutes at the two-second synchronization cadence; expiry fails the agent
instead of installing an empty authority island.

## Consequences

- Adjacent rollout becomes a two-phase fleet handoff without temporarily
  disabling policy or interpreting missing encryption state as Native.
- Fresh installations use the same barrier, so Required-by-default cannot race
  initial key, plan, path-proof, and map publication.
- Node-local APIs remain available while readiness truthfully stays false,
  making the causal blocker observable without granting packet authority.
- A controller outage with already committed local authority still follows the
  existing revalidation path; the barrier does not discard last-known-good
  state.

## Verification

The focused agent test proves that an empty island cannot satisfy the attachment
predicate, including the otherwise quiescent/no-revalidation state. Strict
Clippy covers the implementation. `make encryption-phase9-openshift-gate-test`
checks the staged rollout contract. Exact runtime and qualification revision
`1dbef4d6a75a6c2b97c276267f7b43d95b6cae41` then passed the complete fresh
three-Node dual-stack Kind gate. The evidence JSON SHA-256 is
`d73bd08db6992c8ddd1855f0f5173d6fa39d91b46fee389500e41ae2f4da8708` and the
packet-capture SHA-256 is
`2f944751d201d33efddf417dd842d20aa0ce95a82d83da10df9a3b7389492ed7`.
Only an image tuple built from that runtime may return to cl02.
