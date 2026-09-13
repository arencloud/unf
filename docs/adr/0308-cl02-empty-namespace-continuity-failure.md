# ADR 0308: cl02 Empty-Namespace Continuity Failure

Date: 2026-09-13

Status: live regression reproduced; runtime repair pending

Runtime `54f5511`, qualifier `4aa6119`, passed exact fixture adoption, all 24
original Native allowed cases and eight unsolicited denials, then completed
the 45-second continuity observer on cl02. Of 208 fresh connections (26 per
target), ten failed with wget network-error exit 4 and about one-second
timeouts. All eight same/cross-Node PodIP/translated-Service IPv4/IPv6 paths
were affected. The observation stream completed; this is not either of ADR
0307's earlier observer failures. No pass evidence is emitted.

Empty-namespace create/relabel/delete occurred between Unix milliseconds
`1789294091305` and `1789294105142`. Failures began at `1789294121937`, after
the delete completed, and continued through the final sweep. Before/after
controller observations both reported five converged agents, unchanged Pod
count 199, Service count 93, identity revision 311, Service revision 263 and
topology revision 132022. Policy revision alone advanced from 583 to 587.
The source unconditionally bumps that revision on namespace label changes,
even without endpoints; staged policy/encryption revision mismatch is therefore
a concrete candidate mechanism, not yet a packet-map-level attribution.

Controller logs in the surrounding five-minute capture contained retention
warnings, not ERROR records. All UNF Pods retained zero restart counts. Thus
Ready, converged and no ERROR logs are insufficient evidence of packet-path
continuity. The later public-generation capture was after fixture cleanup had
started; do not present its moving generations as the exact failure-time map
contents. No keys, maps, frontiers or journals were reset.

| Ignored continuity evidence | SHA-256 |
|---|---|
| `s1-continuity-4aa6119-cl02/continuity/probes.jsonl` | `7b1a63dfa299a817c84dc318365fb706dd8bda2b55aa590956cd0e74e606d1f5` |
| `s1-continuity-4aa6119-cl02/continuity/summary.json` | `2c872f2fa32bef15e7690f0a07ba9587e9bbcf3ae927a259acfb61ec551d6655` |

Do not run this new slice on Kind until cl02 passes. Add regressions for
semantic no-op namespace changes while preserving label storage, initial
nonzero authority, occupied namespaces and synthetic host-network peers. Keep
all policy/Required encryption checks intact. Qualify any repaired runtime on
cl02 first; this experiment alone does not close wider traffic-update atomicity,
Required coverage or Phase 9.
