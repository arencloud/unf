# ADR 0357: Matching Kind Held Namespace Observation Qualification

Date: 2026-09-14

Status: verified for isolated held-descriptor snapshot/retirement behavior

After ADR 0356's cl02 pass, retained Kind worker `unf-s1-571379d-worker` runs
the identical immutable fixture:
`quay.io/arencloud/unf-test-tools-dev@sha256:a2d65ae84e2b0d04c789b22c4be078fa040eec2eb8e907801b967efec348a38c`.
The OCI archive is imported into the existing isolated runtime; the exact
digest-named reference is checked before execution. No cluster is recreated.

All thirteen checks pass: five positive snapshots; four exact rejections for
MTU drift, namespace-path replacement, peer movement and target deletion; four
sticky retirements after restoration. Each new observation is constructed
explicitly. Observers exit successfully, private namespaces are removed and
the fixture Kubernetes Namespace is deleted. Node UID and live `f984db9` images
remain unchanged. Final three-agent state is fresh and converged at policy
revision 46 / Service revision 19 under Native.

Evidence: `.artifacts/p9-veth-observation-b9cc5a8-kind`.
Raw fixture archive SHA-256:
`a2c4e332c8a3df4709dbe406b6430eea8da06ae75e27eaf58b5de77a08d530f6`.

Controller, all agents and init installers are reviewed before and after,
including the full fixture interval. Current/rotated agent CRI files are also
reviewed: 201,000 lines / 119,179,031 decoded bytes, including older runtime
history. No current-container restart, ERROR, panic, OOM or verifier rejection
is observed. Startup/activation/proof retries and substantial per-packet INFO
volume remain tracked; this is not a resource-efficiency or clean-log claim.

Both platforms now qualify this snapshot/retirement API. Neither result grants
continuous packet-time authority: holding namespace descriptors does not
prevent peer movement between observations. L3 still requires packet-time
source/target lifetime evidence, authenticated banked publication and
policy/Service/egress-first consumption. L4/L5 replica coverage, full Phase 9
lifecycle and S1–S5 remain open; no release pins are promoted.
