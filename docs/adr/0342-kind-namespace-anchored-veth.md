# ADR 0342: Retained Kind Namespace-Anchored Veth Qualification

Date: 2026-09-13

Status: isolated matching Kind slice verified

After ADR 0341 is committed and pushed, retained Kind worker
`unf-s1-571379d-worker` runs the identical source `a83b4c5` image
`quay.io/arencloud/unf-test-tools-dev@sha256:f64e73ac1c4ad0f9fef4fa5495aaac84b43eb631d58dfa266501bcb5a8e7c9bd`.
Its OCI archive manifest is checked before import into the retained isolated
runtime. Candidate and predecessor adapter hashes match cl02 exactly.

The entire four-private-namespace qualifier passes: the old adapter accepts
both cloned-peer CHECK and replayed ADD; the candidate rejects both with the
namespace-anchored reciprocal-pair diagnostic. Original-handle restoration
recovers CHECK without journal mutation. All fourteen negatives, four
interrupted-creation states, legacy replay, UID/address reuse and normal
cleanup pass. The fixture namespace is absent and the Node UID is preserved.

Result SHA-256, identical to cl02:
`1d5445fd9c6c9ff5e643c6ba61bbf36c3a5f26bea0ddeddd88808fb75a9eca70`.
Private fixture archive SHA-256:
`bd34b2a6e6027360e3289c1d30e0497f4d12a42ede4febc551410122d61b954b`.

All live UNF containers remain Ready with zero restarts; init installers remain
Completed/exit 0. Controller and all three agents converge at policy revision
44 / Service revision 19. Live runtime remains `450de80`; no installed CNI,
BPF, attachment journal, encryption frontier or key authority is changed.

Controller, all agents and installers are reviewed in captures covering the
before/test/after intervals. The final API read is only 639 lines / 339,312
bytes because current CRI files have rotated. Retained current and rotated
agent files supply 219,003 lines / 129,848,221 bytes of overlapping coverage.
They contain eighteen proof-assistance, fourteen plan-synchronization, six
activation and three startup-barrier warnings; only one proof-assistance
warning is new in this test window. No observed ERROR/panic/OOM, verifier
rejection or stopped-dataplane match appears. Per-packet INFO amplification
remains an S3 resource finding, not a successful load-envelope result.

This verifies a stricter kernel snapshot boundary on both platforms, not a
continuous device-lifetime capability. L3's authenticated consuming boundary,
L4/L5, complete lifecycle Q and S1–S5 remain open. Full Phase 9 platform rows
and release pins are not promoted.
