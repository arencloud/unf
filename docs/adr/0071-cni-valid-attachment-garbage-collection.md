# ADR 0071: CNI garbage collection reconciles durable attachments from runtime authority

Status: Accepted and implemented locally; live OpenShift rollout and reboot
qualification in progress

## Context

The cl02 primary-CNI reboot gate found a lifecycle gap that ordinary DEL and
same-IP reuse tests could not expose. After two abrupt worker reboots, the
worker's journal grew from 14 to 25 and then 36 Ready attachment records while
only ten UNF workload links and ten running non-host-network Pods existed.
Twenty-six records referred to links that no longer existed. CRI-O could not
issue DEL for every pre-reboot sandbox, so their dual-stack leases remained
durably reserved.

CNI 1.1 defines GC and supplies the runtime's authoritative
`cni.dev/valid-attachments` set. UNF already parsed the command but treated it
as a no-op. Inferring validity from host interface presence alone would be
unsafe: a valid attachment can be temporarily incomplete during recovery, and a
foreign same-named interface must never authorize journal deletion.

## Decision

The agent transaction API adds a non-mutating, network-scoped attachment list.
It is an additive schema-v2 operation because existing request and response
shapes remain unchanged. Results are ordered by the complete durable
`AttachmentKey`, use an exclusive cursor, and are limited to eight records per
page. Validation rejects invalid networks, cursors, and limits. A maximal page,
including the allowed 4,096-byte namespace paths and 253-byte identifiers,
serializes below the existing 64-KiB transaction bound.

`unf-cni` accepts the exact CNI 1.1 fields `containerID` and `ifname` and
builds an in-memory set of valid tuples for the configured network. It walks
every bounded page and reconciles records absent from that set:

- `aborting` records repeat exact route/link cleanup and complete abort;
- `preparing`, `ready`, and `deleting` records persist or resume
  `deleting`, perform route-first exact cleanup, and complete deletion; and
- valid records are not inspected or changed.

The existing ownership rules remain authoritative. Foreign routes, links, or
other cleanup conflicts retain the durable record and lease. GC continues with
the remaining stale records and returns retryable CNI error 11 after attempting
the full scan. Error reporting is bounded to eight record-specific samples plus
an omitted count. Agent or journal unavailability also fails retryably; GC
never claims success without durable ownership access.

An empty valid set is meaningful runtime authority and removes all safely
cleanable attachments for that network. UNF does not derive the set from
Kubernetes objects, link names, or process state.

## Verification

`make cni-lifecycle-test` passes the complete link, routing, protocol,
state/API, strict-lint, and privileged atomic lifecycle suite. The privileged
fixture creates valid and stale dual-stack attachments in separate namespaces,
supplies only the valid tuple, and requires the stale routes, link, record, and
lease to disappear while the valid attachment remains exact.

The same fixture injects an MTU ownership conflict into an earlier stale
attachment. GC returns a bounded retryable error, retains that deleting record
and its lease, still cleans a later stale attachment, and preserves the valid
one. Restoring the owned MTU and repeating GC completes cleanup. Unit coverage
locks the specification's `containerID` spelling, network scoping, ordered
pagination, limit rejection, and maximal serialized page size.

The broader static gate also passed:
`make fmt-check lint test ebpf support-matrix-check
openshift-primary-cni-package-check`.

## Consequences

Abrupt runtime loss now has an authoritative, retryable path to reclaim stale
UNF links, routes, journal records, and dual-stack leases without weakening DEL
or exact ownership. The local implementation is not yet credited as cl02 reboot
qualification: new immutable agent/CNI images must be rolled out, the observed
stale records must be reconciled, and a clean reboot must prove journal/link/Pod
cardinality returns to equality.

This decision does not claim that CRI-O invokes GC at a particular interval.
The live gate must record the runtime invocation behavior and may issue one
explicit standards-shaped GC request as a diagnostic or recovery action. CRI-O
fault injection, exact teardown, no-CNI behavior, and reprovision recovery
remain separate exit criteria.
