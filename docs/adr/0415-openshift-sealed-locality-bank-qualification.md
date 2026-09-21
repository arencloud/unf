# ADR 0415: OpenShift sealed locality bank qualification

Date: 2026-09-21

Status: isolated kernel-decision scope verified; production integration open

After the retained failures and repairs in ADR 0414, cl02 worker
`bc-24-11-27-b6-49` (unchanged UID
`1ade5ebe-7f24-4f35-b9d4-aca5b13b1c2b`) passes the entire immutable diagnostic:

`quay.io/arencloud/unf-test-tools-dev@sha256:a409a19d3ec1f7590ece4c7deef7aff7e3adb799e92ceeb4e200a0f35d236088`

Source is `b432bec`. Public digest/source-label verification and binary hashes
are retained. Locality ELF SHA-256 is
`93da80e50201d45841b1253d489328518bdc5f593518f9329d6e9345dca0faa3`.
This is a disposable privileged Pod on the actual RHCOS/SELinux kernel, with
private namespaces/bpffs, not a live-agent upgrade or production map mutation.

## Verified scope

All 28 existing native-observation checks pass. The two-endpoint/four-address
bank then passes real kernel loading, exact shared/program map-ID checks,
native BTF geometry, both device seeds, seed destruction, map freeze/readback,
final observation and original-cut publication. There are nineteen explicit
non-transmitting packet decisions: four redirect requests and fifteen drops.

- Current IPv4/IPv6 requests select the exact target, decrement hop limit and
  write its verified source/destination MACs.
- Empty dispatch, unarmed fence, wrong source/target identity, stale epoch or
  routing, wrong destination port, unknown schema and absent DSR continuation
  deny.
- Withdrawal denies; republishing alone does not rearm the applied fence.
- Removing the actual target routes denies both families. Restoring those
  identical routes while the exact devices/leases remain live permits again.
- Actual journal BeginDelete revokes the source nonce before link deletion;
  both families deny. The original bank cannot republish across the changed cut.
- Foreign-runtime and foreign-context publication attempts reject.

The process exits zero without restart. Private links/namespaces, bpffs pins and
the exact-UID Kubernetes Namespace are removed. All 116 pre-existing production
CNI records remain byte-identical to the pre-attempt snapshot, including the
107 legacy records. Both live fleets remain on `45d85d5`, Native baseline.

## Logs and retained evidence

Current regular/init logs and exact retained/rotated CRI logs are reviewed.
The post-test twenty-minute window has 464 warnings: 410 bounded flow-history
retention, 41 peer-proof retries, twelve bounded topology-history retention and
one attestation-row rejection. Retained CRI contains 2,873 warnings in 21
categories, including earlier planned-recovery retries; these overlapping
inventories are not additive. No ERROR, observer failure, cap hit, partial CRI
record or non-JSON record is found. Earlier current logs show all five agents
advancing through epoch 6500 after earlier attestation-row retries; this is not
an uninterrupted progress guarantee. Warnings remain stabilization findings.
All current UNF Pods are Ready with zero restarts; fresh ordinary reports
converge on all five nodes at policy 373 / Service 193.

Evidence prefix: `.artifacts/p9-kernel-bank-b432bec-cl02`.
Result SHA-256:
`93dbfefbb985de3fdf9fa307880fa2965785afd6a0484169fa4c3cf17aa1ca75`.
Complete fixture log SHA-256:
`a9cb8af956e4be2df2778c1ce98d8f95f800e4f5c5eded6944c8ee4478ef5bb8`.
All earlier failed attempts remain recorded in ADR 0414.

Matching Kind passed all 28 native checks and nineteen bank decisions but
failed the final silent cleanup assertion. That complete attempt is retained
under `.artifacts/p9-kernel-bank-b432bec-kind`; it is **not** a platform pass.
Its temporary Namespace was removed and production journals remain identical.
Read-only inspection of the Kind host finds kernel-created `maps.debug` and
`progs.debug` entries in bpffs. The fixture now compares the exact typed,
inode-bound inventory of its fresh private mount before/after the test,
rather than assuming all kernels create empty filesystems. No filename is
excluded and any new, missing or replaced object still fails. Stage and private
link inventories make future cleanup failures explicit. Repeat the corrected
immutable fixture on cl02 first, then Kind. Current Kind regular/init logs
retain two peer-proof warnings and no ERROR; retained logs are also captured.

This fixture fabricates
trusted policy input and tests redirect requests, **not application delivery**.
It does not close policy/Service/egress integration, protocol compatibility,
real-agent startup/migration, restart continuity or L3/L4/L5/Q. No Phase 9 or
stabilization gate, live baseline or release pin is promoted by this result.
