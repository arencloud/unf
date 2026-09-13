# ADR 0343: Device-Reference Local Delivery Investigation

Date: 2026-09-13

Status: isolated investigation fixture implemented; kernel qualification pending

ADR 0342 verifies an attachment snapshot, not its future lifetime. A Required
local delivery branch cannot simply remember an interface index and later
redirect to whichever device owns that number. Nor may route drift send local
Required plaintext toward an underlay device. These are open L3 prerequisites.

Investigate an existing Linux primitive, not a claim of a newly invented
algorithm: TC mirred redirect actions retain a device reference. Upstream
[Linux 5.14's action implementation](https://github.com/torvalds/linux/blob/v5.14/net/sched/act_mirred.c)
clears that reference on device unregister and drops redirect traffic when
the target is absent or down. This suggests a lifetime-safe final delivery
mechanism, but does not establish RHCOS behavior, UNF integration or performance.
Raw ifindex-based BPF redirect alone is not treated as such a capability.

`hack/verify-local-delivery-device-lifetime.sh` and its pinned-base container
build isolate four private network namespaces. The fixture exercises:

- IPv4/IPv6 UDP payload delivery through one target-bound action.
- Rename continuity without rebinding, down-state denial and up-state recovery.
- Deletion followed by a different device with the same index, MAC addresses
  and destination IPs, plus ordinary forwarding routes toward that replacement.
- Denial through the old action, then positive delivery only after explicitly
  creating a fresh action bound to the replacement device.

Receiver processes and sockets are checked positively; action snapshots and
exact payloads are retained. The first fixture deliberately emits no verified
result: raw target-reference and positive attempt/drop statistics require a
strict independent gate after the actual cl02 JSON format is inspected. Shell
syntax and diff checks pass; no kernel behavior is marked verified yet. Run
cl02 first and only advance to identical-image Kind after the full gate passes.

No live workload interface, CNI configuration, BPF map or transport generation
is changed. The fixture's private forwarding switches and TC rules are not a
production implementation. Candidate integration would still need authenticated
exact-address placement, immutable source-attachment fencing, banked publication,
post-policy/post-Service semantics, foreign-mark preservation, independent
readback, cleanup/restart handling and measured resource/throughput costs.
Existing schema-2 encrypted transport recovery must remain intact. L3, L4/L5,
Q and S1–S5 remain open; no release pin or platform row is promoted.
