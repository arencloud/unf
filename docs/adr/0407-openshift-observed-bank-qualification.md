# ADR 0407: OpenShift Observed Locality Bank Qualification

Date: 2026-09-21

Status: disposable observed-bank fixture verified on cl02; matching Kind pending

The ADR 0406 implementation and corrected packaging at `b9a824a` pass on cl02
Node `bc-24-11-27-b6-49`, UID `1ade5ebe-7f24-4f35-b9d4-aca5b13b1c2b`, using
`quay.io/arencloud/unf-test-tools-dev@sha256:6ce5d918c67fc5132065a94561d55112556fde5f04a95b96bc89d71cdd27ef0e`.
Public registry provenance and the actual container image ID agree. The
container exits zero without restart on the retained RHCOS/SELinux 5.14 kernel.

All 28 native attachment observation/retirement cases pass. The combined
fixture then prepares two real journal-bound endpoints and four addresses
through the bounded worker and independently replayed fixture placement.
Same-socket netlink namespace cookies match an independent UDP-socket oracle.
Ownership aliases and retained namespace descriptors agree. Route drift and
cancellation retire the complete preparation; restoring a route does not
rearm it. Stale applied context and journal cuts are rejected. Actual journal
teardown revokes the exact lease while preserving the unrelated endpoint.
The test's links, routes, temporary journals and owned namespaces are removed.
No workload packet transmission or production packet permission is tested.

All five existing CNI journals (116 records) remain byte-identical. All five
agents converge at policy 427 / Service 199, and current runtime Pods remain
Ready with zero restarts on unchanged `6d71a30` images.

## Separate encryption health finding — not waived

All UNF regular/init logs are reviewed before, during and after. The final
20-minute window contains 746 warnings: 432 bounded flow-history retention,
299 key-publication failures, six expired-authority recoveries, four proof
assistance failures, three drain/catch-up deferrals and two topology-history
retention messages. There are no ERROR messages or failed/truncated log reads.

Key-publication failures already existed before this diagnostic was deployed.
They include a prepared transition behind the fleet epoch floor and rejected
reciprocal witnesses. A read-only authenticated public-key probe obtains
bootstrap and round responses (200), but the complete attestation-cut response
is 503. Policy/Service convergence and this disposable fixture do **not** prove
encryption-fleet health. Preserve this finding for lifecycle repair and full
current-runtime requalification; do not reset key journals or mark Q verified.

Evidence: `.artifacts/p9-observed-bank-b9a824a-cl02`, with log/journal/controller
snapshots under `.artifacts/p9-observed-bank-cl02-*`. Evidence JSON SHA-256:
`1fab4e395e9ab3f53889a6a07d56fc35a77ca1a487de6089389acd93c033fa1a`.
Timestamped test log SHA-256:
`96ed8eedbc6a8b2f15d1452c02b5edc82d8e05697c11411585285abdd930159e`.
The failed initial packaging build remains recorded in ADR 0406.

Matching-image Kind is next. Frozen device maps, immutable program publication,
actual agent/packet consumption, migration, L3/L4/L5/Q and Phase 9 remain open.
