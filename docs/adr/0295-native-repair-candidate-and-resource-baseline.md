# ADR 0295: Native Repair Candidate and Pre-Repair Resource Sample

Date: 2026-09-13

Status: staged cl02 deployment and focused Native gate passed; Kind pending

## Immutable candidate

Runtime `571379d9378b83cb15e1f54fbf7f825c3bfd4708` contains ADR 0294's Native
coverage repair. Both components are built from that committed source, then
published to the authorized development repositories:

| Component | Quay manifest SHA-256 |
|---|---|
| controller | `ebb0d51bbf9b2568416c70fd981fa00a8432f05dc7a9ef874d5df2c59bc9128f` |
| agent | `ac8f9554368efa76e39ac113c15d4f4b52124afd4db6e19fe7c9c90644e5ea93` |
| unchanged test tools | `e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352` |

The release record resets Kind to pending for this new runtime; ADR 0292's
older passes are not transferred to it. The controller keeps its 2-CPU/2-GiB
ceiling. No map ABI, wire schema, crypto or key lifetime changes are introduced.
The build uses the isolated temporary image store, without pruning user images
or rebalancing the host filesystem. Credentials remain ignored and mode 0600.

## cl02 result and remaining platform failure

Qualifier `31ce13a19e1f4be974f9cc59b70f50da133feadb` passes the controller-first,
node-serial deployment with all five agents converged and kube-proxy absent.
The focused Native gate then passes all 16 allowed cases and eight unsolicited
reverse denials across TCP/UDP, IPv4/IPv6, PodIP/Service and same/cross-worker
paths. Restricted non-root fixtures run without an SCC exemption. Namespace
absence and final five-agent convergence pass. Evidence JSON SHA-256:
`1e9242df973c866af5ab8fff6346523a0af8402e26adbc3bc268fb67d8aa758d`.

This is not complete platform recovery: the original ingress-operator Pod on
control-plane Node `bc-24-11-47-5e-1b` still times out against the DNS Service,
direct DNS Pod on its actual port 5353 (UDP and TCP), and direct OAuth TLS
transport. Earlier direct-DNS attempts without `-p 5353` incorrectly tested
port 53 and cannot establish backend DNS health; the corrected-port attempts
also fail. The OAuth transport-only probe skips certificate validation, so it
makes no certificate-trust claim. Six unhealthy operators remain.

The worker fixture pass does not close this control-plane-node/older-workload
failure, Required locality/replica/reply coverage, or Phase 9 requalification.
Keep those failures visible and diagnose their actual map/attachment/path state.
No completed Kind result is claimed for this runtime yet.

## Short pre-repair cl02 sample

After the old-runtime fixture was removed, two cgroup samples approximately
34 seconds apart measured runtime `cb59e90` with its Native baseline and six
unhealthy operators. This is a short diagnostic window, not a healthy-idle,
heavy-load, throughput or supported-capacity benchmark. The local image build
was outside the cluster; operator reconciliation and normal cluster traffic
continued. CPU is the cgroup `usage_usec` delta divided by each sample's wall
interval. Memory columns are end-of-window observations, not synchronized peaks.

| Component/Node suffix | CPU cores | Cgroup MiB | Process RSS MiB |
|---|---:|---:|---:|
| controller / 89-00-a5 | 1.335 | 80.9 | 95.5 |
| agent / 89-00-a5 | 0.155 | 605.1 | 15.1 |
| agent / 7f-81-3f | 0.248 | 662.8 | 22.6 |
| agent / 47-5e-1b | 0.253 | 635.6 | 22.2 |
| agent / 27-b6-49 | 0.180 | 343.4 | 20.0 |
| agent / 74-2b-8d | 0.176 | 602.6 | 20.2 |

Cgroup accounting and RSS measure different things; do not infer a leak or
attribute their difference exclusively to BPF. All sampled memory OOM counters
are zero. Agent cgroups have no CPU/memory maximum; the controller remains
bounded. Include `memory.stat`, pinned map memory, shared/file accounting and
Node ownership before assigning memory budgets. A restarted cgroup is not an
equal-workload comparison to an older one.

Private raw samples and Pod identity/config snapshots are retained under
`.artifacts/s1-cb59e90-native-{before,after}` and the derived summary JSON. S1
must repeat measurements after correctness and operator-health recovery, with
workload inventory and longer controlled windows. S2–S5 remain unverified.
