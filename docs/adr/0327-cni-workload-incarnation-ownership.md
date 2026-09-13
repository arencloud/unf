# ADR 0327: CNI Workload Incarnation Ownership

Date: 2026-09-13

Status: CNI ownership prerequisite verified locally; kernel/platform qualification pending

## Why this precedes locality admission

The durable CNI attachment previously identified network, sandbox container ID,
interface, namespace path and MTU, but did not retain the Kubernetes Pod UID.
Joining a controller address owner to that record could therefore silently
assume a Pod incarnation. Locality admission must not make that assumption.

ADD and CHECK now parse one bounded `K8S_POD_UID` from runtime CNI arguments.
Missing UID remains explicitly unbound for non-Kubernetes and legacy callers;
empty, duplicate, malformed and oversized UID arguments fail before allocation.
No complete CNI environment is logged. The runtime-supplied UID is ownership
metadata, not independently authenticated Kubernetes placement.

## Versioned durable and kernel ownership

CNI transaction schema 3 carries an optional immutable workload UID. Schema-2
requests remain supported for unbound records, with schema-2 successful replies.
They cannot introduce, read or mutate bound records, including through listing,
abort or deletion. No binding is stripped to manufacture legacy compatibility.
New CNI binaries require a schema-3 agent; there is no silent client downgrade.

Existing schema-2 journals open without rewriting or reallocating leases.
Unbound-only writes retain schema 2. A document containing any bound attachment
uses schema 3, which old binaries reject. Removing the final bound attachment
through the normal deletion lifecycle leaves an unbound schema-2 document.
Schema-1 migration remains supported without inventing UID ownership. Legacy
documents claiming a workload UID are rejected. An existing unbound attachment
can replay under a newer runtime without becoming bound. A bound attachment
requires the exact UID on ADD/CHECK; omitted or changed UIDs conflict.

New bound veth endpoints carry `unf:cni:v2` aliases containing a domain-separated
SHA-256 cookie over the complete network/container/interface key and Pod UID.
Host and peer roles remain distinct. Existing production apply, readback and
deletion checks consume these aliases. Missing or changed bound aliases cannot
be repaired by trusting only the interface name or MAC. Legacy v1 alias and
partial-state recovery behavior is unchanged. UID storage uses `Box<str>` rather
than reserving mutable string capacity; this is not a measured fleet saving.

The cookie is not a signature, packet permission or proof that an ifindex cannot
be reused. Privileged host mutation remains outside its authenticity guarantee.
The locality consumer still needs current placement replay, exact attachment
and route readback, generation binding, invalidation and final delivery checks.

## Verification and rollout boundary

Focused tests cover UID parsing, durable restart, changed/omitted UID rejection,
legacy replay without rebinding, schema-2 request fencing, forged legacy
ownership, malformed UID rejection before allocation, failed-write rollback,
full-key/UID alias separation and missing/foreign/replaced kernel alias checks.
All-features workspace tests pass: 778 passed, 26 explicitly ignored. Strict
all-target/all-feature workspace Clippy, formatting and staged secret scan pass.
No live CNI binary, journal, map, route, image pin or encryption default is changed
by this source milestone. A bound journal must not be rolled back to a v2-only
agent; deployment must update the agent before the new CNI is invoked.

The cl02 preflight reviews controller, all five agents and every installer over
a bounded 20-minute window. All containers are Ready with zero restarts; 428
history-retention warnings and one rejected reciprocal key-attestation
publication remain recorded. No ERROR/panic/OOM/verifier failure is found in
that window. This is a baseline observation, not new feature qualification or
complete historical-log coverage.

Next: isolated production CNI/kernel lifecycle validation on cl02 before Kind,
then L3's consuming locality integration. L3/L4/L5/Q and S1–S5 remain open.
