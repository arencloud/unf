# ADR 0418: Paired sealed-bank socket qualification

Date: 2026-09-21

Status: isolated socket-delivery scope verified, cl02 then matching Kind

The complete ADR 0417 `kernel-delivery` suite passes on actual cl02 RHCOS/SELinux
first, then persistent Kind, on identical source `35f9e1b` and image:

`quay.io/arencloud/unf-test-tools-dev@sha256:f934aa4362d5e5543ee109456b2250b6f3b67bc1bc6f693510e33422903d6b11`

Each platform passes all 28 native checks, nineteen non-transmitting kernel
decisions and 24 actual socket observations: eight allowed and sixteen denied.
TCP/UDP IPv4/IPv6 deliver exact unique 1,200-byte payloads and native replies
under current authority and after restoring the identical target routes.
Unpublished/unarmed/wrong-identity/withdrawn/not-rearmed/route-absent cases deny
both UDP families. Actual journal nonce retirement denies both TCP and UDP
families while the links remain alive. Unexpected socket errors do not count
as denials. The complete ordered matrix, including negative observations, is
retained, not inferred from redirect return codes.

Both processes exit zero without restart. Only loopback remains in all private
network namespaces; private bpffs inventories match; temporary exact-UID
Kubernetes Namespaces are removed with explicit absence readback. Schema 2
reports both successful cleanup and completed socket testing. All existing
production journals remain byte-identical to fresh pre-test snapshots. No
legacy CNI attachment is recreated. Live runtime remains `45d85d5`, Native,
with no production image, release pin or cluster networking changes.

## Logs and evidence

Current regular/init and retained/rotated logs are reviewed. The cl02 current
window has 445 warnings: 423 bounded flow-history retention, sixteen peer-proof
retries, four topology-history retention and two reciprocal attestation-row
rejections. Successful key activations continue afterward (observed through
epoch 6529 on the diagnostic worker); this is not an uninterrupted-progress
claim. Retained cl02 logs contain 3,338 warnings in 21 categories. Kind has four
current peer-proof warnings and sixty retained warnings in twelve categories.
These overlapping inventories are not additive. There are no ERROR entries,
observer failures, partial or non-JSON CRI records. Warnings remain S1 findings.

Evidence prefix: `.artifacts/p9-kernel-delivery-35f9e1b-{cl02,kind}`.

| Evidence | SHA-256 |
|---|---|
| cl02 result | `5f88b359600f710471d4ebe8402c1424d2891a90f39cfabcd0b82000d417eb54` |
| cl02 full test log | `0fab7c06acafe825bcfc59bea76240b5243b4d1afd1cc0ec259c92f44b905d06` |
| Kind result | `1d3d4a70caa01c20f89294b6d786482217050ee18e40830de51fa5bb783b227e` |
| Kind full test log | `21ba25b84c89c17d0d7f1d015ffe3663c24cd0a03c32fdaa9b8326ae3caf0f16` |

This proves isolated forward-bank application delivery with synthetic trusted
input and native replies, **not** production policy, Service translation,
source egress, encryption selection or reverse-path composition. It is not
throughput/CPU/RSS, concurrency, restart continuity or full protocol-coverage
evidence. Next complete production admission coordination and packet wiring,
then L4 mixed local/remote replicas, L5 matching runtime and Q lifecycle.
L3/L4/L5/Q and Phase 9 remain open.
