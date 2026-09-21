# ADR 0431: Paired mixed-MTU and selection-readback qualification

Date: 2026-09-21

Status: verified isolated diagnostic; production composition remains open

The complete `kernel-agent-startup` diagnostic passes cl02 first, then persistent
Kind using the identical immutable `5f03031` image:

`quay.io/arencloud/unf-test-tools-dev@sha256:2e75bb2acb468f219fc852dcc46e5e09327ff15606a75ab896b2a085609364dd`

The clean detached `5f03031` qualifier checkout and fixed source/image exclude
concurrent later packet-bridge edits. Actual startup-agent SHA-256 is
`31d43fb4cb42120e4cd097dd0116238df8872f78f2b31603a4bc191bd003bf7c`.

Each platform passes all 28 native observations, the real 1400/1450-byte mixed
MTU cohort and wrong-uniform-provider rejection, 19 kernel-bank decisions,
eight coordinator decisions with actual selected-program/fence readback,
eight successful/16 denied TCP/UDP dual-stack exchanges, durable old-reader
refusal, exclusive map ownership and all five actual-agent startup scenarios.
Identical-coordinate writer completion does not silently restore selection.
Diagnostic processes exit zero with no restarts; exact-UID namespace removal
and private link/bpffs inventory cleanup pass.

Existing production CNI journals are byte-identical before/after on both
platforms. Kind's empty control-plane journal remains absent. All production
UNF Pods are Ready with zero restarts and retain the `45d85d5` Native baseline.
No production map, journal, key, route, deployment or release pin was reset.

Log review covers every current regular/init container plus retained CRI logs,
including rotation. No observer errors, cap hits, partial/non-JSON records or
production ERROR entries were found. cl02's current window contains 422 WARNs:
418 bounded flow-history retention, two topology retention and two peer-proof
retries. Its retained files contain 6,132 WARNs across 21 categories, including
earlier recovery, key/plan retries, qdisc, compilation and synchronization
observations. Kind has three current peer-proof WARNs and 68 retained WARNs
across 12 categories. These warnings remain evidence, not a warning-free or
heavy-load stability claim. Expected negative-case startup errors are preserved
in the diagnostic logs, separately from production logs.

Evidence roots: `.artifacts/p9-kernel-agent-startup-5f03031-{cl02,kind}` and
`.artifacts/p9-producer-5f03031-*`.

| Artifact | SHA-256 |
| --- | --- |
| cl02 result | `a9b78690b3e71b38895b121db6ef6d46419f7640ab23c6f6cfbcf60d5fbb963a` |
| cl02 diagnostic log | `f59d4f3e6393545e626d77f5534d552e6649abfbd6d05887e6ee1e801abab901` |
| Kind result | `4f17041ad7742a84e1ff61d77a72e0ff648a49358d44f8aa33297a3d81ebdf0a` |
| Kind diagnostic log | `cb9d60f70eb7c63c97025245a8a63ea1afcca8fd6292acd532f721a06ff15d33` |

This qualifies the expanded mechanisms, not the real publisher's entire event
loop, production identity/route writers, later all-plan acquisition, main packet
bridge, reverse-Service policy composition or restart continuity. L3/L4/L5/Q
and S1–S5 remain open.
