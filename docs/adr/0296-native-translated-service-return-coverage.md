# ADR 0296: Native Translated Service Return Coverage

Date: 2026-09-13

Status: expanded cl02 regression passed; matching-image Kind pending

ADR 0295's 16-case worker fixture passes, but the original platform checks need
separate evidence. After initial post-rollout failures, a synchronized capture
at 04:10:53 UTC shows a direct DNS request and reply reaching both Pod veths,
and OAuth's SYN-ACK reaching the client. Direct DNS returns the Kubernetes
Service A record; the transport-only OAuth probe returns HTTP 200. This late
success does not erase the earlier failures or establish a recovery-time bound.

Read-only map lookups show all four original DNS/OAuth identity directions now
have explicit Native authority in both banks, with identical encryption config
before/after lookup. The diagnostic 30-second capture reports 60 captured,
66 received-by-filter and zero kernel drops; its watchdog exits 124 as expected
for this bounded diagnostic, not the release ciphertext gate's exit-zero proof.
No private journal or kernel state was modified.

DNS through `172.30.0.10:53` still times out. Its ready EndpointSlice publishes
port 5353 backends; `trafficDistribution` is `PreferSameNode`, with Cluster
internal traffic policy. A translated-port or selection interaction is a
hypothesis, not yet an attributed defect. Direct attempts on the wrong backend
port 53 are excluded from backend-health claims.

Expand the portable Native fixture to 24 positive cases: keep all previous
PodIP and same-port Service checks, add TCP 18080→8080 and UDP 53→5353 Services
for both server Nodes and both IP families. Policy still allows only the backend
ports. Retain all eight unsolicited reverse denials, strict observation handling,
restricted Pod security, bounded resources and positive cleanup/convergence.
Run the expanded gate on cl02 first; Kind and broader Phase 9 remain pending.
Do not infer DNS Service recovery from success against direct Pods.

## Expanded cl02 result

Runtime `571379d`, qualifier `f6f3c6097a44cc627df6d932b786aa4a2199be13`,
passes all 24 allowed cases and eight unsolicited reverse denials, followed by
Namespace absence and final five-agent convergence. Evidence JSON SHA-256 is
`9097ae0f10282a14e5b480a8607dccd5ba4e8b8f1da909833770478daccd3bec`.
No translated-port defect is established by this passing fixture.

The original DNS Service also subsequently returns ten correct A answers in
ten probes between 04:15:30 and 04:15:40 UTC. Authentication, console, ingress
and kube-controller-manager recover; Insights and network remain unhealthy.
Preserve the preceding timeouts: these steady-state successes do not prove
continuity across reconciliation, rollout or Namespace/workload churn. Qualify
the same immutable images on fresh Kind next, then add a controlled continuity
test before claiming that the transient failures are resolved. Required
locality/replica/reply contracts and the full Phase 9 lifecycle remain open.
