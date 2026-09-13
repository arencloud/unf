# ADR 0310: Stable-Policy Native Continuity Failure

Date: 2026-09-13

Status: cl02 deployment passed; continuity failed; Kind unchanged

Runtime `42907aa96c77b7d6ce7e5c875d476cd7a43fd2aa`, qualifier `660285b`,
uses ADR 0309's exact immutable images. The guarded cl02 rollout passed,
including embedded revisions, five-agent convergence and host checks. All
new UNF Pods were Ready with zero restarts. No authority or dataplane state
was reset. Retained Kind remains on the previously qualified `54f5511` images.

The adopted Native fixture passed 24 allows and eight unsolicited reverse
denials. Its completed 45-second namespace-churn observation then failed one
of 232 fresh HTTP connections: remote-server Service IPv4, Unix milliseconds
`1789296358169`, wget exit 4 after 1,011 ms, during namespace deletion. Each
of eight targets had 29 observations; the other 231 succeeded. This is a
failed qualification, not a pass with a tolerated failure or a throughput SLO.

Before/after policy revision remained 468, identity 291, Service 203 and
topology 132606. The skipped-invalidation counter increased by four. Thus the
new no-op handling worked for this window, but cannot explain away or claim
to repair the remaining packet interruption. A public-only five-Node capture
started after the failed sample, while probing was still running: all journals
reported generation `1789296264787`, policy 468, Service 203, no transports,
and the controller frontier had five receipts. These sequential durable
observations are not failure-time BPF-map or packet captures.

Both owned namespaces were positively absent after failure cleanup. All-Pod
logs were inspected before and after deployment and around the failed window,
including every reported current/init container; no Pod had a previous restart
to inspect. There were no captured ERROR records. Warnings are not all benign:

- One policy rejects an IPv4 ipBlock containing 17,891,328 addresses against
  the current 1,024-address limit; two host-network `healthz` named-port mappings
  conflict (9259/9260 and 9441/9440). These are existing compatibility gaps.
- Existing clsact creation reports netlink exclusivity, followed by attempted
  attachment; readiness and the deployment host checks passed.
- Activation/testimony HTTP 503 retries and one rejected plan request occurred
  around startup and fixture setup. The latter still lacks specific server
  rejection detail. They must not be dismissed as proof of healthy encryption.
- During the failed sample's surrounding 10:45:48–10:46:05 UTC window, captured
  warnings were bounded-history retention only. No ERROR log or restart is
  required for a packet failure.

| Ignored evidence | SHA-256 |
|---|---|
| `s1-namespace-42907aa-cl02-deploy.json` | `ba7309e927ab346bf384bb036c2f4ac20b3ea68ee694c8c5fcc305f4921de2af` |
| `s1-namespace-42907aa-native-cl02/continuity/probes.jsonl` | `368dfe79bb5ab2076f181fd68a3fdf52b859c20a924cadfd584a7b8f743f08f0` |
| `s1-namespace-42907aa-native-cl02/continuity/summary.json` | `1710ffd02bb95ba3765ed6c74e28d30d59467bf68184b841c2d28c5c431f01f5` |

Next: improve bounded connection-stage diagnostics and capture the exact
fixture packet path without retrying failed samples into success. Keep this
window and ADR 0308's earlier failure. Do not upgrade Kind before cl02 passes.
General update continuity, Required locality/replica/reply, full Phase 9
lifecycle and S1–S5 remain unverified; no CPU saving is inferred from skipped
work alone.
