# ADR 0404: OpenShift Kernel Incarnation Gate Qualification

Date: 2026-09-21

Status: disposable journal/kernel gate verified on cl02; matching Kind pending

Source and qualifier `bbb5a65` pass on cl02 Node `bc-24-11-27-b6-49`, UID
`1ade5ebe-7f24-4f35-b9d4-aca5b13b1c2b`, with the published immutable image
`quay.io/arencloud/unf-test-tools-dev@sha256:9f3db2b9b2d50b054d21f25b2bdb260ca68926ab9719b55d8bede7180a7fa81e`.
The actual container image ID matches. This is the retained RHCOS/SELinux
OpenShift installation and its 5.14 kernel, not a workstation substitute.

The production library creates fresh anonymous kernel maps with exact
32-byte keys, 8-byte values, requested capacity and program-read-only flags.
The actual CNI journal callback removes a lease before an intentionally failed
durable write; the restored Ready record does not restore the old lease.
Current-cut reissue gets a new serial, preserving stale-serial rejection and
the unrelated attachment's lease. Idempotent deletion, attachment replacement,
foreign/reopened journals and gates, and capacity failure with continued
revocation all pass. The container exits zero with zero restarts.

The test creates no network links or production pins and sends no workload
packets. Its temporary journals/maps and owned Kubernetes Namespace are cleaned
up. All five existing CNI journal files, containing 116 records, remain byte
identical. All five agents converge at policy 413 / Service 193; current runtime
Pods remain Ready with zero restarts on unchanged `6d71a30` images.

All current UNF regular/init logs are reviewed before, during and after. The
final 20-minute window has 441 warnings: 434 bounded flow-history retention,
five proof-assistance and two topology-history retention; no ERROR or log-read
failure is present. This does not erase the recurring warning findings or
prove sustained-load stability.

Evidence: `.artifacts/p9-incarnation-gate-bbb5a65-cl02`, with before/during/after
log, journal and controller snapshots under `.artifacts/p9-incarnation-gate-cl02-*`.
Evidence JSON SHA-256:
`01aa53c61da0947b57bf94121f158e09dc8284ee50dfd621b53cdd9332d66d0d`.
Timestamped test log SHA-256:
`eb5b7f6916fce167035f053f6aa9a1efa2ac3dbf8def36836138ded99dabc4ae`.

Matching-image Kind execution follows. This gate verifies kernel/journal
invalidation, not a production packet consumer, concurrent packet recall or
application delivery. Authenticated immutable-bank integration, startup fencing,
L3/L4/L5/Q and full Phase 9 remain open; no live locality permission is enabled.
