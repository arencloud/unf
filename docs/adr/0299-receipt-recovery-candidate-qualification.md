# ADR 0299: Receipt Recovery Candidate Qualification

Date: 2026-09-13

Status: immutable candidate published; live gates pending

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
