# ADR 0405: Matching Kind Kernel Incarnation Gate Qualification

Date: 2026-09-21

Status: disposable journal/kernel gate verified on both platforms

After ADR 0404's cl02 pass, persistent Kind passes the identical source
`bbb5a65` diagnostic image
`quay.io/arencloud/unf-test-tools-dev@sha256:9f3db2b9b2d50b054d21f25b2bdb260ca68926ab9719b55d8bede7180a7fa81e`.
Actual image ID matches. Node `unf-p9-20260921-worker` retains UID
`bab6dc45-3f5d-4cc1-8c7f-d3c66af25b5f` and kernel `7.2.5-200.fc44.x86_64`.
The runner requires the matching successful cl02 evidence before Kind execution.

The exact map geometry and program-read-only flags, full-nonce/serial issuance,
journal-callback revocation before a failed write, unrelated-lease preservation,
fresh-serial reissue, idempotent deletion, attachment replacement, foreign/open
journal and gate rejection, and capacity-failure revocation all pass. The
container exits zero without restart. Private maps/journals and the owned
Kubernetes Namespace are removed; no production pin, link or policy is modified.

Both existing worker journal files remain byte-identical. The control-plane
journal remains absent, independently checked against no non-host-network Pods.
All three agents converge at policy 44 / Service 19; runtime Pods remain Ready
with zero restarts on unchanged `6d71a30` images. Current regular/init and
retained agent CRI logs are reviewed before/during/after as applicable. The final
current window has one proof-assistance warning; retained logs have 75 warnings,
including previous recovery/test events. These overlapping windows are not
independent totals. There is no ERROR, observer failure or byte-cap truncation.

Evidence: `.artifacts/p9-incarnation-gate-bbb5a65-kind` and
`.artifacts/p9-incarnation-gate-kind-*`. Evidence JSON SHA-256:
`8a526a14d404c636bd4dcfffa24313514e3586bbeb37548fb26b1f3ad267149c`.
Timestamped test log SHA-256:
`c89f27298b9cfceb1cd1673eefab5bf22ecdb31132cdaff788b8c5d496677b21`.

The kernel/journal revocation prerequisite is qualified on both deployed
kernels. The agent still has no production locality bank. Authenticated bank
construction, source/target device lifetime, packet-policy-first consumption,
route checks, startup fencing, L3/L4/L5/Q and full Phase 9 remain open. No
packet-delivery or sustained-load/resource improvement is inferred from this gate.
