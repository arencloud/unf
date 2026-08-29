# ADR 0072: CNI delete intent survives transaction-service outages

Status: Accepted, implemented, and live clean-reboot recovery verified

## Context

ADR 0071 added authoritative CNI 1.1 garbage collection after abrupt cl02
reboots left 26 attachment records whose sandboxes and links had vanished. The
digest-pinned GC implementation was then rolled to all five Nodes and an exact
standards-shaped request reconciled every runtime cache: 36 stale records were
removed across the cluster and every Node returned to equality between running
non-host-network Pods, CRI-O result caches, durable attachment records, and UNF
host links.

A subsequent clean worker reboot exposed the earlier failure in the lifecycle.
CRI-O invoked DEL for all ten old sandboxes between 11:28:07 and 11:28:08, while
the rebooted agent did not publish `/run/unf/cni.sock` until 11:28:38. CRI-O
removed its result cache after each failed call. Replacement ADD calls began at
11:28:50 and created ten new attachments, so the worker journal grew from 10 to
20 even though only ten Pods and links existed. Manual CNI 1.1 GC restored
exact cardinality, but periodic GC alone cannot preserve an intent that the
runtime discards before the local transaction service is ready.

Returning success for an unavailable DEL without first retaining exact durable
ownership would leak resources silently. Returning an error is also
insufficient because the observed runtime legitimately removed its cache after
the call. The delete intent therefore has to survive independently of both the
runtime cache and the agent socket.

## Decision

The production `unf-cni` executable owns a bounded, network-scoped deferred
delete queue under `/var/lib/unf/cni/v1/pending-deletes`. This path is the
default when `deferredDeleteDirectory` is absent, which preserves recovery for
pre-reboot CRI-O cache entries containing an older otherwise-compatible network
configuration. Primary-CNI manifests also set the path explicitly.

When DEL cannot reach or complete the local socket transaction, the plugin
atomically persists the exact network, container ID, and interface name before
returning an empty successful CNI result for a transport failure. A persistence
failure never reports success. Agent-originated conflicts, incompatible
schemas, ownership failures, and other non-transport failures retain the queued
intent but return their original fail-closed error.

Before ADD, DEL, CHECK, or GC performs its requested operation, the plugin
orders and drains every deferred delete for that network through the existing
route-first, two-step durable agent lifecycle. A record is removed only after
the agent confirms deletion. If the plugin stops after agent completion but
before queue removal, the repeated exact delete remains idempotent. If draining
fails, ADD, CHECK, and GC fail closed. DEL first persists its current key so
that one blocked older record cannot lose a newer runtime intent.

Queue documents use schema version 1 and a deterministic
`<network>/<containerID>/<ifname>.json` path. Files are atomically published by
write, file sync, rename, and parent-directory sync; they require mode 0600, a
single hard link, exact path/content agreement, and no symlink component.
Directories are owner-owned and mode 0700; the plugin refuses rather than
changing a weakly protected configured root. An owner-owned advisory lock
serializes enqueue and the complete per-network list/delete/complete drain, so
concurrent kubelet ADD calls cannot overtake or duplicate queue consumption.
Listing is deterministic and publication is capped at 65,536 records per
network. Malformed, weakly protected, linked, or over-capacity state fails
closed rather than being skipped.

## Verification

Unit tests prove durable ordered idempotent enqueue/completion, exact schema and
path checks, symlink/permission/hard-link rejection, and the production Unix
socket path: an offline DEL succeeds only after queue publication, then the
next ADD sends the exact deferred `BeginDelete` before attempting its own
allocation and removes the completed queue record.

`hack/verify-cni-protocol.sh` independently invokes the compiled executable,
requires the offline DEL to return empty success, validates its mode-0600 exact
document, proves ADD remains fail closed while the queue cannot drain, and
requires the record to remain. The OpenShift package fixture requires the
explicit owner-only host path. The complete local gates pass:

`make cni-lifecycle-test` and
`make fmt-check lint test ebpf support-matrix-check
openshift-primary-cni-package-check`.

Exact source revision `8f4165a00451713edf57b041a8a3cc9516f09793` is
published and anonymously pullable as controller digest
`sha256:532ed06a91ab636b27ac8dca7457b24d10cf5765bc4b7904333da5eebed08d85`
and agent/CNI digest
`sha256:17efacea6d20d2bf26cef5f0b5adfbf03c99c05f694d793de931a0f036329c86`.
The unchanged test-tools content resolves to
`sha256:f57a7ee9668d6b87f4e00c4e8df9240b8889c6ee50f817ea1e884732b2f42b13`.

The `8f4165a` images rolled serially to all five cl02 agents with zero restarts,
then the controller established a new epoch with all five agents exactly
converged. Every Node retained equal attachment/cache/link counts; every queue
was empty, mode 0700, and explicitly configured. The pre-reboot review then
found that the initial lock protected publication/listing but not the complete
agent-driven drain. Several simultaneous kubelet ADD calls could therefore read
the same records, remain safe through idempotence, but incur avoidable retries.
The reboot was deliberately withheld, the lock scope was expanded, and a
concurrency test now proves enqueue waits for the entire drain.

The first superseding publication was rejected before pinning or rollout
because its supplied embedded full revision did not equal `git rev-parse`.
The provenance-correct exact revision
`15866c44bca4953b5401d0cdce66a65d3462af42` is published and anonymously
pullable as controller digest
`sha256:51e195e2b69ee28fa5f81d51b4bfa43c28f3d2ce3033d94fe2e0ce994c471b0e`
and agent/CNI digest
`sha256:a6552fbb7eec17d92c40ad5ef89c127faaec86daffb8e4727bb49eb9370ad9a8`.
The unchanged test-tools digest remains
`sha256:f57a7ee9668d6b87f4e00c4e8df9240b8889c6ee50f817ea1e884732b2f42b13`.

The provenance-correct images rolled serially to all five cl02 agents and then
to the Recreate controller. All components exposed the exact embedded revision.
Four agents and the controller rolled with zero restarts; the control-plane
agent on `10.50.60.200` restarted once after a projected-token request returned
403 during cache startup, then recovered without intervention. Before reboot,
all five agents converged on epoch `7679427618012921356` and every Node retained
equal Pod/attachment/cache/link cardinality with an empty queue.

Worker `bc-24-11-74-2b-8d` then completed a real reboot from boot ID
`8a61e7f5-65ed-427e-860c-806887a5fcda` to
`dae93ed0-0ff4-4eab-916a-efac30d3a078`. CRI-O invoked DEL for all ten old
sandboxes at 12:24:40, before the agent restored eight last-known-good remote
routes and published its CNI socket at 12:24:49. The plugin returned no CNI
error because each exact delete was durable. Ten replacement ADDs began at
12:24:53 and drained the serialized queue before allocation.

Without manual GC, the worker stabilized at exactly ten running non-host Pods,
ten Ready attachments, ten CRI-O caches, ten UNF links, ten unique IPv4 leases,
and ten unique IPv6 leases. No deferred JSON record remained; only the expected
per-network lock remained. Eleven BPF map files, fourteen protocol-196 routes
per family, the same canary Pod UID, and direct cross-worker IPv4/IPv6 HTTPS
were restored. A subsequent hold retained the exact cardinality and restart
counts. All five kubelet proxy and Node-local DNS checks passed, 34 operators
other than the pre-existing external Insights condition were healthy, and the
controller reported five expected, reporting, fresh, and converged agents with
matching identity 228, policy 435, and route 1 revisions.

## Consequences

Runtime DEL is now availability-tolerant without weakening durable ownership:
the runtime may forget its cache while UNF retains and fences the exact cleanup
work. New allocation cannot overtake retained cleanup after the agent becomes
reachable, and CNI 1.1 GC remains the independent authoritative reconciliation
path for losses that occur outside an observed DEL.

The queue is a local recovery journal, not a second attachment database. The
agent journal remains authoritative for leases and kernel ownership, and only
the existing exact agent delete lifecycle can release them. A permanently
conflicted record deliberately blocks subsequent lifecycle operations for its
network until ownership is repaired or an operator resolves it. Cross-network
queues are independent.
