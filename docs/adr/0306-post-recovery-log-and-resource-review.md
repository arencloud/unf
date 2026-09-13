# ADR 0306: Post-Recovery Log and Resource Review

Date: 2026-09-13

Status: bounded operational review complete; continuity and load work pending

At the user's request, review every UNF Pod/container on cl02, then retained
Kind, after ADRs 0304–0305. Collect the previous 20 minutes, capped at 5,000
lines/2 MiB per container, including installer containers; collect previous
container logs only if restart counts are nonzero. All observations succeeded,
all runtime Pods were Ready, and all restart counts were zero. Retain raw logs
only under ignored owner-only artifacts and scan them for secrets before review.

cl02 (approximately 09:29–09:49 UTC): 444 controller WARN records reported
bounded flow-history checkpoint retention. One agent WARN at 09:48:45 reported
a rejected reciprocal key-attestation row. No ERROR record was observed. The
warning omits the server's specific rejection detail, so its exact historical
cause is not established. A subsequent verified-TLS authenticated read for
that same agent returned HTTP 200 for bootstrap, round and complete-cut APIs:
five epoch-704 proposals and four peer acknowledgements for the recipient.
The earlier warning remains recorded; current success does not prove absence
of recurring races or successful Required traffic. Insights and network
operators remain unhealthy.

Kind (approximately 09:30–09:50 UTC): 5,738 parsed INFO records, no WARN/ERROR
records. Most were per-flow logs (5,440); 226 were Service outcomes, 32 safe
transport-free epoch retirements, 30 key activations and 10 proactive rotations.
This identifies logging volume worth profiling, not permission to remove useful
telemetry or evidence of acceptable logging cost at scale.

The separate cl02 cgroup/process sample spans approximately 46 seconds per
container, without a synthetic load generator. Resolve the actual UNF PID
inside each container cgroup (agents use host PID namespaces; host PID 1 must
not be measured as the agent). All six samples showed zero OOM kills.

| Component | CPU cores over interval | Process RSS MiB | Cgroup MiB |
|---|---:|---:|---:|
| controller | 1.272 | 156.3 | 139.0 |
| agent .200 | 0.128 | 194.5 | 239.4 |
| agent .203 | 0.091 | 216.6 | 259.4 |
| agent .201 | 0.080 | 173.2 | 211.0 |
| agent .204 | 0.085 | 186.2 | 224.0 |
| agent .202 | 0.083 | 282.1 | 315.4 |

RSS and cgroup accounting have different shared-page attribution and capture
times; do not sum them or call these synchronized fleet peaks. Agent kernel
accounting was about 47.5–48.0 MiB each, not exclusively BPF memory. This is
not a healthy-idle or heavy-load benchmark, and is not a controlled comparison
against previous restarted containers. Controller CPU remains a profiling
target; no resource limits, retention bounds or log levels were changed.

Ignored evidence: `.artifacts/s1-log-review-{cl02,kind}-34ad6de/`,
`.artifacts/s1-log-review-cl02-key-cut/`, and
`.artifacts/s1-log-review-cl02-resources{,-before,-after}` (summary `.json`).
Continue with controlled namespace-change continuity before declaring Phase 9
complete, then measured S1–S5 optimization and load qualification.
