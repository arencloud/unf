# ADR 0299: Receipt Recovery Candidate Qualification

Date: 2026-09-13

Status: cl02 staged rollout passed; expanded Native traffic failed; Kind held

ADR 0298's runtime candidate is
`b5bf6c6f0f249ce1e23371835623acbf0ea5affc`. Publish and anonymously verify
immutable development image digests, then deploy controller-first and
node-serially on cl02. Run expanded Native traffic coverage before updating
retained Kind `unf-s1-571379d`. Preserve its mixed-generation journals and
partial controller checkpoint to test recovery rather than a clean reset.
Full Phase 9 qualification and stabilization remain open.

Both development images are built from that exact committed runtime and
anonymous Quay manifest reads match their pushed digests:

| Component | Manifest SHA-256 |
|---|---|
| controller | `467847001378b5c98596b37a723eab81895396ecbd7395977679161367869a2b` |
| agent | `19293ffc065feb90ade8df12adef3c7a869426311ad86164f22120edb73c1539` |
| test tools, unchanged | `e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352` |

The release record retains `qualificationOrder: openshift-first` and pending
Kind evidence. These digest checks prove published artifact identity, not
runtime traffic or recovery correctness.

## cl02 result

Qualifier `6717935` passes the controller-first/node-serial staged deployment,
with all five agent receipts and the same public admitted generation
`1789275605720`, zero container restarts, and kube-proxy absent. This is not a
successful packet or mixed-cursor recovery qualification.

The expanded Native gate then fails its first allowed IPv4 Service request
after the initial Pod-IP probes. At a correlated observation all agents report
policy/Service convergence at `535/203`, but the retained encryption generation
is still bound to `581/230`. Authentication, console, ingress and
kube-controller-manager become unhealthy again; Insights and network were
already unhealthy. The owned fixture is removed and the failure is retained;
no passing evidence JSON exists for this run.

An authenticated plan request over verified TLS returns 204 with no successor.
Public key bootstrap reports fleet floor 569; agent warnings show transition
568 behind that floor and deferred retirement. The controller code requires a
complete, common ready key epoch before producing even a fully Native plan.
ADR 0300 separates that coupling from the receipt repair and plans a narrow
key-independent Native path. A later recovery or retry cannot erase this
bounded gate failure. No keys, maps or journals were cleared.

One follow-up bulk public-journal capture was interrupted by an exec EOF and
contains incomplete files; it is not a complete fleet proof. The earlier
post-rollout five-Node capture and the persisted public controller frontier
remain valid within their separate capture windows. Authentication tokens used
for the diagnostic requests stayed in process memory/curl stdin, never artifacts.

Kind remains on `571379d`, with its original two-receipt checkpoint and mixed
cursors retained. The new runtime has not been deployed there because cl02
traffic did not pass. Full Phase 9 and S1–S5 remain open.

## Correctly scoped pre-candidate resource observation

The earlier agent RSS figures are withdrawn in ADR 0295: agent Pods use
hostPID, so PID 1 was host systemd. This repeat on runtime `571379d` selects
exactly one `/usr/local/bin/unf-component` executable from each container's
`cgroup.procs`, checks that its PID is unchanged across both samples, and
collects cgroup `memory.stat` separately. Missing/ambiguous process selection
fails the sample. The initial extended attempt also failed on unavailable
`memory.pressure`; the corrected sampler explicitly records that optional
interface as unavailable rather than inventing a PSI value.

| Component / Node suffix | Window seconds | CPU cores | Cgroup MiB | UNF RSS MiB | Cgroup kernel MiB |
|---|---:|---:|---:|---:|---:|
| agent / 47-5e-1b | 39.4 | 0.228 | 249.0 | 209.9 | 47.3 |
| agent / 7f-81-3f | 39.5 | 0.205 | 284.2 | 241.2 | 47.7 |
| agent / 89-00-a5 | 41.6 | 0.145 | 198.7 | 166.2 | 47.5 |
| agent / 27-b6-49 | 41.5 | 0.141 | 315.8 | 282.2 | 47.8 |
| agent / 74-2b-8d | 40.9 | 0.195 | 201.6 | 162.7 | 47.9 |
| controller / 89-00-a5 | 41.8 | 1.308 | 101.5 | 119.7 | 1.2 |

This is a short Native-baseline observation with normal platform traffic and
operator reconciliation, not a controlled healthy-idle or heavy-load benchmark.
Insights and network are still unhealthy. All sampled OOM-kill counters are
zero. Inventory records 215 Pod objects (198 Running, 82 host-network, 133
non-host-network) and 91 Services, none with two assigned ClusterIPs outside
the temporary qualification fixture. Pod objects are not equivalent to active
endpoints. End-of-window memory readings are sequential, not synchronized
peaks; cgroup accounting and RSS have different scopes. Kernel accounting is
not an exclusive BPF-memory measurement.

Do not compare these restarted cgroups against ADR 0295's older runtime as a
performance improvement. The controller's sustained CPU use warrants profiling,
and agents need correctly attributed allocation and pinned-map measurements
before tightening their limits. Retain the 2-GiB controller limit; no CPU/memory
limit changes follow from this window. Raw snapshots, process identity, workload
inventory and summary remain under ignored
`.artifacts/s1-571379d-native-scoped-*` and `*-native-stable-*`.
