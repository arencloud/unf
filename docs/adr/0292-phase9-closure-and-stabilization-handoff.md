# ADR 0292: Phase 9 Closure and Stabilization Handoff

Date: 2026-09-13

Status: historical lab passes retained; closure reopened by ADR 0293

The milestone states below describe the closure at the time of these runs.
Subsequent S1 diagnosis found uncovered Native locality and reply failures;
ADR 0294 starts their repair. These passes do not qualify that repair or the
remaining Required locality/return contract work.

## Verified tuple and order

Runtime `cb59e9080a4cce5544c1ae3c69974233d53d8c52` passed the complete strict
cl02 gate first, then fresh Kind with the identical controller, agent and
test-tools manifests recorded in ADR 0291. No runtime rebuild occurred between
the platform runs. Historical attempts remain part of the record.

| Platform | Qualifier | Evidence JSON SHA-256 | Capture SHA-256 |
|---|---|---|---|
| cl02 | `dbefd3e41257a6c801523967bcc29e15236b40a9` | `5950ed9152825209424c3203eeb0cec1d2fe4df5e0b90228ac2893b89bd3a942` | `c7b7c44a701840385dc8ab08cd34d46bca0ff85580d92617ca33ea8ec2500304` |
| Kind | `8fa15a1bcd8e3a0853c090474c9a9e97832468d5` | `04e9d300396bf88a717723b477f71e30af082e12d34fcb1cf338941115fa839f` | `c342805731911eaf75982b95c98812541c9297e68bf378b09fa3d36310fe3d11` |

cl02 completed at 02:04:15 UTC in 1,420 seconds; ADR 0290 records its complete
five-Node RHCOS/SELinux/CRI-O results and persistence observations. Kind's full
gate completed before 02:47:17 UTC on three Debian 12 Nodes, Kubernetes 1.35.0,
containerd 2.2.0 and host kernel 7.1.4-204.fc44.x86_64. ADR 0291 records the
explicitly repackaged node image and unchanged configuration/RootFS provenance.

## Kind result

- Default-Required and explicit-selective dual-stack PodIP/Service traffic pass.
- Eight Required probes report actual network denial while eight Native probes
  succeed during owned-link outages; observation failures cannot count as deny.
- Capture spans 02:40:26–02:40:50 UTC, explicitly stops after the fault window,
  exits zero and reports zero kernel drops. Offline counts are 238 WireGuard,
  zero Required plaintext and 299 Native plaintext frames. Raw tcpdump reports
  537 captured and 553 received by filter; do not reinterpret kernel-drop checks
  as a claim that every packet received at the stop boundary was captured.
- Source replacement recovers generation 1789267267784; natural rotation reaches
  worker epochs 7/8; controller replacement admits successor 1789267417336 with
  epoch 8 on both workers. No pending generation remains in those snapshots.
- Independent history verification covers revisions 60–514, retaining 512
  records with two intentional evictions and zero reported upstream loss.
  The completeness claim remains retained-window-only.
- The committed performance-ledger verifier and 32 sequential dual-stack
  Service requests pass. Their 9.171-second client-loop duration includes exec
  overhead and is not a throughput, packet-latency or CPU-efficiency benchmark.
- The full Phase 8.5 dual-stack egress lifecycle passes in coexistence. Encryption
  cleanup positively reports zero owned links/rules/routes on all three Nodes.
  Version-scoped primary-CNI cleanup jobs and no-CNI rollback pass on every Node.

The private artifacts are archived under `.artifacts/phase9-cb59e90-*`; raw logs,
pcap, history and cleanup snapshots are retained. The dedicated Kind cluster is
removed after the test and the host inotify setting restored. cl02 retains the
qualified images and its original Native baseline; qualification is not a
request to leave a cluster-wide transport migration enabled.

## Closure boundary and next work

Milestones 9.1–9.9 are Verified for their documented bounded scope. The release
record now names real matching-image Kind evidence instead of pending evidence.
Phase 9 closure is not a production-readiness or unrestricted-scale declaration.

Continue the stabilization plan with a commit/push per completed step, testing
cl02 before Kind. S1 must first investigate internal DNS and direct Pod-endpoint
timeouts behind six unhealthy cl02 operators, then capture attributable resource
baselines and feature limits. Keep the unsafe `DisableMultiNetwork` configuration
condition visible rather than masking it. Preserve intermittent migration
timeouts and initial Kind bootstrap exits as reliability findings. S2–S5 must
measure control-plane/dataplane costs, steady growth, saturation, interactions,
outages and recovery under reproducible equal workloads. Do not reduce memory
limits based only on restarted cgroups: pinned BPF memory and Node accounting
must be included. No claim of unlimited scale or competitor superiority follows
from these lab gates.
