# ADR 0312: Expired Service Reverse-Tuple Collision

Date: 2026-09-13

Status: cl02 packet-path failure attributed; regression-backed repair next

Runtime remains `42907aa`, qualifier `f9c2f96`. A second cl02 continuity run
passes the 24 allows/eight denials, then fails one of 224 fresh connections.
The new diagnostic fields identify a TCP-connect timeout, not a stalled HTTP
response: remote IPv6 Service, source `fd01::c:59680`, destination
`fd02::67d4:18080`, sample Unix milliseconds `1789297014271`.
Policy revision remains 488; four unnecessary invalidations are skipped.

Paired worker captures show the SYN at `1789297014.279451` entering the
source Pod's host veth, but no corresponding source underlay transmission or
destination arrival. Nearby IPv4 and IPv6 connections succeed. Both tcpdump
processes were explicitly stopped and reported zero kernel capture drops.
The 96-byte snap length truncates some IPv6 TCP options; the addresses, ports
and SYN flag are visible. This is a bounded textual test-traffic capture, not
a complete payload or loss-free-network claim.

An untruncated controller flow-history query for the surrounding receipt-time
window contains one source-Node drop for this client/Service/backend, action 2,
reason 9 (`SERVICE_EVENT_REASON_PAIR_INSERT_FAILED`). Receipt time is later
than packet time; history does not carry the client source port. The paired
packet and exact map-key observations provide that missing tuple binding.

A read-only lookup of the exact reverse key
`fd01:0:0:2::11:8080 -> fd01::c:59680`, TCP/IPv6/reverse role, finds an old
mapping to **different** frontend `fd02::a0f3:8080`, Service revision 191.
Its monotonic `last_seen_ns` is `135218570834800`; a subsequent source-Node
uptime observation is `160077.01` seconds. The age is approximately 24,858
seconds, versus the defined 300-second TCP lifetime. No map entry was changed
or removed. The source code's reverse insertion uses `BPF_NOEXIST` but does
not reclaim an expired incumbent before treating insertion failure as denial.
This explains the observed dropped SYN with unchanged policy/generation.
It does not retrospectively prove ADR 0310's uncaptured IPv4 failure had the
same cause, or make occupied live tuples safe to overwrite.

The observer setup initially attempted the agent service account and was
rejected by its admission guard before the traffic gate ran. The guard was
not modified. Successful captures used a dedicated temporary namespace and
tokenless capture account with a namespace-scoped privileged-SCC RoleBinding.
A separate temporary reader mounted the existing map directory read-only and
performed only map metadata and exact-key lookup. Both observer namespaces
and both traffic/churn namespaces were positively removed. No keys, journals,
frontiers, production maps or Nodes were reset. Kind remains unchanged.

| Ignored evidence (prefix `s1-native-f9c2f96-cl02-`) | SHA-256 |
|---|---|
| `paired-isolated/gate/continuity/summary.json` | `1aff03654a79bfeadae318d1626ed7ef191245c356e7385aa0344e699ab916ce` |
| `paired-isolated/gate/continuity/probes.jsonl` | `7542acb69c18d628dca80edb6de8bd6c8fff0cd14af902ac647c2051f2d7b324` |
| `paired-isolated/unf-native-observer-source.packets.log` | `bf72e00eda2f139c85f8d1ec6de23fd8b2f28d68f3f836c1510fdaf5e9712367` |
| `paired-isolated/unf-native-observer-destination.packets.log` | `fb5785373963dd6b1577fe224f0cfc3b50ed56af0fb149b0971948b8c5de52d4` |
| `reverse-key/reverse-key.json` | `b584f60c3d07475a48fd4919894ee70f55194a6aa3c18e7dac2f684042c6872b` |
| `flow-window.json` | `8346a24b589273ead77d6f8790d7f576da4964264f1a3536bbd76d4a72de078e` |

Next repair must prove expired-slot reuse, preserve live owners, and avoid
deleting a successor through an old paired key. Exercise IPv4/IPv6 and
forward/reverse ownership, expiry boundaries, partial pairs and insertion
failure. Do not use unconditional overwrite, longer timeouts, periodic broad
map clearing or a policy/encryption fallback. Active reverse-tuple collisions
are a separate translation-design boundary; no unlimited-connections claim.
After local regression/verifier checks, qualify exact images on cl02 before
Kind. General update continuity, Required coverage, full Phase 9 and S1–S5
remain open.
