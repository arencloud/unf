# ADR 0331: OpenShift Interrupted CNI Creation Qualification

Date: 2026-09-13

Status: isolated cl02 recovery slice verified; matching Kind pending

ADR 0330's production CNI adapter and expanded qualifier pass on cl02's
RHCOS worker `bc-24-11-27-b6-49`, retaining Node UID
`1ade5ebe-7f24-4f35-b9d4-aca5b13b1c2b`. Source revision:
`baaa725c3514a23e6db4203f76642b00de5fe5a5`. Anonymous registry inspection
confirms the immutable image and matching OCI revision label:
`quay.io/arencloud/unf-test-tools-dev@sha256:95a9286327290d5bda418db3c079e69455572e801f3ab93399987e6e57ff87e9`.

SHA-256 evidence:

- Production adapter: `97feafa727c23130203ddf5e862497a4ca4deeb2f0e9add55dd5b4d2fbd2c756`.
- Result JSON: `ea0a45a6305169dd7c2fdb70ac77d4b76ba2f6515aa7f46c6aa579e2812d4f68`.
- Private fixture archive: `7d00d7dddb5bc6a92f9cc502f94c1df4c12b42dcec0411c0c926fdff31ac9a40`.

The test reconstructs four interrupted states from durable Prepare: an
unsealed pair, peer-only seal, fully sealed host-up pair, and deletion from
unsealed Preparing. Production resume retains the exact creation nonce and
host interface index; it cannot recreate the pair to manufacture recovery.
Twelve diagnostic-checked rejections and the earlier legacy/UID/restart,
dual-stack route/alias drift, address-reuse and normal cleanup cases pass.
These are constructed interruption states, not a claim of exhaustive crash
injection at every instruction or concurrent privileged-host adversary coverage.

The tokenless, zero-restart test Pod runs in its own namespace under the
observed `node-exporter` SCC, without host mounts or host PID access. Its
separate network namespaces and owned Kubernetes namespace are removed and
absence is checked. No live journal, CNI installation, BPF pin or runtime image
is changed. Both live fleets still run `67c2772`.

Controller, every agent and installer logs are retained before/during/after.
The final 20-minute window contains 409 bounded flow-history warnings, two
peer-proof-assistance warnings and two bounded topology-history warnings.
The preflight also retains two rejected reciprocal key-attestation publications.
No observed file reaches its tail/byte cap; the final collection has 416 lines /
96,123 bytes. No ERROR, panic, OOM, verifier rejection or stopped-dataplane
match is found. All live UNF containers remain Ready with zero restarts.
These warnings remain stabilization findings, not a clean operational-history
claim. No previous-container log exists for these zero-restart containers.

Matching-image Kind is next, after this result is committed and pushed.
Live rollout, authenticated locality consumption, L4/L5/Q and S1–S5 remain
open; this isolated recovery gate does not close a full Phase 9 platform row.
