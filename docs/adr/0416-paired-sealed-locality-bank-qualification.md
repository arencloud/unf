# ADR 0416: Paired sealed locality bank qualification

Date: 2026-09-21

Status: isolated kernel-decision scope verified on cl02 then Kind

The corrected `fd416df` diagnostic passes on actual cl02 RHCOS/SELinux first,
then the persistent Kind worker, using the identical immutable image:

`quay.io/arencloud/unf-test-tools-dev@sha256:27cb70e8d9e98e1ec8392d43d2d2eb24bba4f4e6e9df37bc5be6984d47128d58`

Both runs pass all 28 native observation checks, nineteen non-transmitting
kernel decisions, exact shared-map binding, sealed bank publication, route
invalidation and nonce retirement. Both private link inventories finish with
only loopback; before/after bpffs typed inode inventories match exactly. Kind's
fresh mount contains kernel-provided `maps.debug` and `progs.debug` throughout,
confirming why the earlier empty-filesystem assertion failed. Neither file is
excluded or deleted. The earlier failed result remains in ADR 0415.

Both complete processes exit zero without restart. Exact-UID diagnostic
Namespaces are deleted. Existing production CNI journals remain byte-identical:
all 116 cl02 records, including 107 legacy records, and the retained Kind
records. Both fleets remain on `45d85d5`, Native baseline; no runtime/release
image pin changes.

## Log review

Current regular/init logs, previous availability and exact retained/rotated CRI
logs are reviewed. The cl02 current window retains 444 warnings: 416 bounded
flow-history retention, nineteen peer-proof retries, eight bounded topology
retention and one reciprocal attestation-row HTTP 400. Successful key activation
continues afterward; this does not assert uninterrupted progress. Retained cl02
logs contain 3,126 warnings in 21 categories. Kind current logs retain four
peer-proof warnings; retained logs contain sixty warnings, including earlier
recovery/convergence retries. These overlapping inventories are not additive.
No ERROR, observer failure, partial or non-JSON CRI record is found. All current
UNF Pods are Ready with zero restarts. Warnings remain stabilization findings.

Evidence prefix: `.artifacts/p9-kernel-bank-fd416df-{cl02,kind}`.

| Evidence | SHA-256 |
|---|---|
| cl02 result | `94d5c40d3c4405182d82a2a9b13f6b38da2ce6e8e3e1b831b76614d3a78bffab` |
| cl02 full test log | `e94d915bbaaf13371a0be04ad3274e06da7b857fa87f8c474e416ac46649fe3b` |
| Kind result | `00ed13ec07fb1d3c06a3e5507c406bc1eac10fb94b618ad2511000d00d59c90d` |
| Kind full test log | `84f3f05a1b8b70774c98241954848fb6dba442447637b63351e724e854174dd2` |

This closes the isolated bank-decision gate, not actual socket delivery,
production policy/Service/egress integration, startup/migration, authenticated
restart continuity or L3/L4/L5/Q. The fixture supplies artificial trusted policy
input; redirect requests are not application delivery evidence. Next add
bounded actual socket delivery/denial checks on these exact private endpoints,
then complete the production consuming boundary. Phase 9 remains open.
