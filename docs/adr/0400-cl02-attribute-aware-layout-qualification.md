# ADR 0400: cl02 Attribute-Aware Native Layout Qualification

Date: 2026-09-21

Status: complete isolated cl02 rerun verified; matching Kind pending

After ADR 0399's regression-backed repair, source `90cb651` passes the entire
cl02 device fixture on unchanged RHCOS kernel `5.14.0-687.39.1.el9_8.x86_64`.
The immutable image is
`quay.io/arencloud/unf-test-tools-dev@sha256:7dfb1ba3ff7078b6d004f50a7e2d7657f763483b3f5c9eb13724e88b0ec52948`.
The diagnostic BPF remains `4ce81c6b…2d47a`; live UNF remains `6d71a30`.

Native metadata exactly matches independent reference offsets and the previous
cl02 digest. Repeated discovery is byte-identical. Native offsets drive all
thirty serial deliveries, forty denials, nine non-transmitting seeds, two
wrong-context rejections and sticky source/target invalidation checks.

Independent movement replay accounts for 40,000 packets: 1,997 exact original
deliveries and 38,003 rejections. Publication replay independently accounts for
40,000 packets: 8,610 allow-generation deliveries and 31,390 deny-generation
rejections. Foreign delivery, socket loss and unobserved redirects are zero.
All 22 publication readbacks, forty empty-dispatch denials, sealing negatives
and five exact old-map retirements pass. These remain isolated mechanism tests.

The fixture's private mounts/namespaces and Kubernetes Namespace are removed;
Node UID and all 116 preexisting CNI records are unchanged. Five fresh reports
converge at policy 410 / Service 193; all current UNF Pods are Ready, zero restarts.
All regular/init streams are reviewed before, during and after. Final window:
447 warnings, no ERROR: 425 bounded flow-history, sixteen proof-assistance,
three topology-history, one reciprocal-key-publication, one expired watch and
one encryption-operations persistence retry. The last warning retains only the
outer ConfigMap-patch context; its underlying cause is not established.

A subsequent read-only durable checkpoint observation at resourceVersion
`9165102` contains generation `1789982863185`, revision `3679875`, matching the
post-test operations API's generation/complete-through sequence. This proves
later persistence, not the cause of the earlier retry or durable recovery under
load. Warning detail and bounded-history churn remain stabilization findings.

Evidence: `.artifacts/p9-device-lease-90cb651-cl02` and
`.artifacts/p9-native-layout-tags-cl02-*`. Archive SHA-256:
`53ba1aaba5533c8e97f2deb8873ce01ab47b65ccfff7d0182055e5336ead5834`.
Result SHA-256:
`b33d29186d8b139ac3e804a21d8b7796fa5e24547978f8c37d2c1a0c87cd1211`.
Retry Kind only with this exact image after this cl02 pass. ADR 0399's failed
Kind attempt remains retained. No production locality or full Phase 9 gate closes.
