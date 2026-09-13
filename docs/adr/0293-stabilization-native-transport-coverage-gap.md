# ADR 0293: Stabilization Found Missing Native Transport Coverage

Date: 2026-09-13

Status: live diagnosis verified; repair and platform requalification pending

## Evidence

S1 followed the passing Phase 9 gates in ADR 0292. Read-only cl02 checks from
the ingress-operator Pod reproduce TCP/UDP DNS timeouts through the Service and
direct DNS Pod, plus direct OAuth Pod connection timeouts. DNS's local readiness
endpoint responds `OK`. Policy explanations allow the DNS request in both
directions of isolation (source egress and destination ingress).

A synchronized, bounded header-only capture on the source Node shows the DNS
request reaching its host veth without leaving toward the DNS Pod. OAuth's SYN
reaches the server Pod; its SYN-ACKs return to the host but do not reach the
client veth. The involved interfaces use the same current UNF ingress/egress
program IDs; all twelve policy/egress/encryption tail slots are populated.

Read-only kernel lookups, fenced by identical before/after encryption configs,
show policy revision 446, service revision 201, egress revision 38, active bank 1
and no encrypted epochs/transports. Both banks lack the ingress-operator/DNS
identity-pair decision. The forward ingress-operator/OAuth pair has explicit
Native authority; the opposite pair is absent. No map, rule or key was changed.

`native_decisions` currently excludes same-Node endpoint pairs and requires an
independent stateless policy allow for each direction. The packet finalizer,
however, requires explicit transport authority even after per-packet policy
has admitted a same-Node packet or a stateful reply. These missing records
explain the captured Native failures. A missing lookup is not a reason to add
a permissive dataplane fallback.

Private observations are retained in `.artifacts/s1-cl02-correlated-*`,
`s1-cl02-dns-*-explanation.json`, `s1-cl02-node-bpf-metadata.log` and
`s1-cl02-policy-pair-encryption-decisions.log`. The first unsynchronized capture
and an unavailable host tcpdump attempt are not causal evidence; the correlated
capture uses the pinned test-tools image and records probe times explicitly.

## Decision and verification boundary

Preserve ADR 0292's real passes, but reopen affected Phase 9 qualification: its
fixtures did not cover these same-Node and policy-isolated-return cases. S1 is
not complete and the cluster is not healthy. Add reproducing regressions before
the repair, keep security-policy enforcement and missing Required authority
fail-closed, and qualify each repaired runtime on cl02 before fresh Kind.

Separate Native coverage from the larger Required locality/replica and
return-path contracts. Do not mark the latter solved by a Native-only repair.
Measure decision-count and compilation/resource changes, preserve hard bounds,
and do not add one tunnel per workload. No credentials or packet payloads are
committed.
