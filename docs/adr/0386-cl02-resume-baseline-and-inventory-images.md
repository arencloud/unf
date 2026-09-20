# ADR 0386: cl02 Resume Baseline and Inventory Image Provenance

Date: 2026-09-21

Status: existing-runtime baseline verified on cl02; candidate rollout pending

Before changing the long-running `f984db9` fleet, rerun the complete selective
Required reply gate with qualifier `3dd7809`. It passes 24 allowed requests
(12 Required and 12 Native), eight unsolicited reverse denials, three real CNI
UID/nonce bindings and retirements, and both placement-candidate retirements.
IPv4/IPv6 TCP/UDP cover cross-worker PodIP, Service and translated ports.
Capture records 203 WireGuard frames, zero Required plaintext, 72 Native
plaintext frames and zero kernel capture loss. Capture exits zero after an
explicit stop; its container lifetime includes waiting for the start marker.

Required admission initially needs retries: path probes time out and receipts
do not cover the exact current generation. It eventually converges without
intervention; Native cleanup also converges. These are retained reliability
findings, not a claim of prompt or interruption-free activation. Final public
reports are fresh/converged on all five Nodes at policy 1108 / Service 362.
The fixture Namespace is absent; no live image, baseline or journal reset occurs.

Evidence: `.artifacts/p9-inventory-baseline-cl02/evidence.json`, SHA-256
`6a0e6039e440bf6ef29edc3186faede7631db8d5d0517d96c08ee5dd23a68b7b`.
Capture SHA-256:
`0fb606a8c35d449614684bc1a8e954dc3be00fdd470c4617daab09c9cfc4bdb6`.
Controller, every agent and installer logs are reviewed before/during/after;
containers retain zero restarts. Final 20-minute logs retain 406 bounded-flow,
81 proof-assistance, 44 plan-sync, 13 bounded-topology, 11 clsact, seven pending
activation, one locality-fetch and one Service-sync warning, with no ERROR.
Earlier windows also retain key-publication retries. Existing operator findings
remain open. Source and destination worker SSH access is verified read-only.

Build and push source `d00707176dfa50b80e2092c02a8171c7f39a9295` to development
repositories only. Anonymous registry inspection, image revision labels and
isolated running version endpoints agree. Controller image:
`quay.io/arencloud/unf-controller-dev@sha256:d316cce192dc45b9baf32bb74ced11161c2f378bd4d085e6517dfb02a6ea6c7d`.
Agent/installer image:
`quay.io/arencloud/unf-agent-dev@sha256:a37618606aff4a57f814f37abaca7567dde0a51f6e4f8938b874cb9f961e6027`.
CNI SHA-256: `812b0e33a46ea705c64af35fe6cf96598bb2dd0bfdad6537bd5934509ff024b3`.
BPF remains `d8551daad5f6222a8b9ddd7b3e7ed5d869bdea53c99b1e8c692f8ec0c205a27d`,
core ABI 15 / encryption ABI 2. An isolated version-check container required
SIGKILL after the ten-second SIGTERM grace period; preserve that shutdown
finding rather than inferring graceful termination from successful version reads.

These images are not yet deployed or runtime-qualified. Next is guarded cl02
rollout and the expanded inventory gate, followed by matching Kind. The retained
Kind environment remains unavailable. L3 packet consumption, L4/L5/Q and S1–S5
remain open; this baseline is not full Phase 9 closure.
