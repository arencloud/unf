# ADR 0401: Matching Kind Native Device Layout Qualification

Date: 2026-09-21

Status: complete isolated native-offset gate verified on both platforms

After ADR 0400's cl02 rerun, persistent Kind passes source `90cb651` on the
identical immutable image
`quay.io/arencloud/unf-test-tools-dev@sha256:7dfb1ba3ff7078b6d004f50a7e2d7657f763483b3f5c9eb13724e88b0ec52948`.
The worker retains Node UID `bab6dc45-3f5d-4cc1-8c7f-d3c66af25b5f` on kernel
`7.2.5-200.fc44.x86_64`. ADR 0399's earlier pre-load failure remains archived.

The native reader handles this kernel's compiler-attribute tags and matches
all independently derived base/split-module layout coordinates, including
namespace-cookie offset 4,672 (cl02 uses 4,096). Repeated metadata/digest output
is byte-identical. Those native offsets drive the actual BPF fixture, not just
an observational status counter.

All seventy serial checks pass: thirty deliveries, forty denials, nine
non-transmitting context seeds and two wrong-context rejections. Full alias
comparison, source/target sticky invalidation and explicit recovery pass.
The 40,000-packet movement matrix has 2,002 original deliveries and 37,998
rejections. The separate publication matrix has 5,398 allow-generation
deliveries and 34,602 deny-generation rejections. Independent replay accounts
for every sequence; foreign delivery, receiver socket loss and unobserved
redirects are zero. All 22 publication readbacks, forty empty-dispatch denials,
unsealed/frozen-write negatives and five exact old-map retirements pass.

Private fixture namespaces/mounts and its Kubernetes Namespace are removed.
Both preexisting worker CNI journals remain byte-identical; the control-plane
journal remains absent, independently checked against no non-host-network Pods.
Three fresh reports converge at policy 41 / Service 19. All current runtime
Pods remain Ready with zero restarts on unchanged `6d71a30` images.

Current regular/init and retained agent CRI logs are reviewed before, during
and after. The final current window contains one proof-assistance warning.
The full retained agent CRI read is 88,746 decoded bytes with 74 warnings,
including earlier recovery/test windows. These overlapping counts are not
independent event totals. There is no ERROR, observer failure or byte-cap gap.

Evidence: `.artifacts/p9-device-lease-90cb651-kind` and
`.artifacts/p9-native-layout-tags-kind-*`. Archive SHA-256:
`ab7e5a4f730cd8055437a835d4b0c59724e25952ec505fcab0571c07add275b1`.
Result SHA-256:
`b2219564003181ccaf06d7c4c3d5596ab86e8b9793ebada84f22fc025caf1163`.

The native layout prerequisite is now qualified on both deployed kernels.
It is still not the authenticated production locality consumer. Kernel
admission, production publication and observed-delivery API claims remain
false. Continue L3's real journal/placement/kernel join, packet-policy-first
immutable-bank integration and explicit migration, then L4/L5/Q. Full Phase 9
and stabilization remain open; no release pins or platform gates are promoted.
