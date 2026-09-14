# ADR 0382: Matching Kind Joint Native Attachment/Route Observation Gate

Date: 2026-09-14

Status: verified for the isolated joint snapshot API

After ADR 0381's cl02 pass, retained Kind passes the identical source `91cc771`
image `quay.io/arencloud/unf-test-tools-dev@sha256:9f519400e453bd4bb704a91ba2a83f6b747681830f4dba33ff2f982b83af65bd`.
The imported manifest and exact digest reference are checked.

At 03:54:25 UTC all 28 ordered observations pass: ten positives, six exact
IPv4/IPv6 host/peer route or neighbor drift rejections, two path/link drift
rejections, one cancelled recheck and nine sticky-retirement checks. The complete
individual response ledger matches cl02 byte-for-byte, including exact missing
route/neighbor roles and counts. Restoration never rearms an old observation;
fresh construction succeeds. Failed/cancelled rechecks expose neither readback
nor retained namespace descriptors. Observer stderr is empty.

Evidence: `.artifacts/p9-native-attachment-91cc771-kind`; archive SHA-256
`37af7a957af15edd30e11b46a0e5f663a673718abf723749c5b693c649bcd1a1`.
Private namespaces and the Kubernetes fixture Namespace are removed; Node UID
is unchanged. All three live reports finish fresh/converged at policy 73 /
Service 19. Regular UNF containers remain Ready with zero restarts and init
installers completed. Both live fleets still run `f984db9`.

Before/during/after controller, agent and installer logs are reviewed, followed
by retained current/rotated agent CRI. The current final window has one
proof-assistance warning. Retained CRI spans 397,664 lines / 235,697,659 decoded
bytes, with twelve proof-assistance and three older activation warnings. No
ERROR, failed observer or current byte cap is observed. Existing INFO-volume
and reliability findings remain stabilization work.

Both kernels now qualify the joint snapshot API. This is not atomic route/link
locking, actual CNI journal authentication, current placement authority or
packet-time Required locality permission. Next is a stale-safe real journal
inventory join, followed by authenticated/banked packet consumption. Full Phase
9 and stabilization S1–S5 remain open; no scale-efficiency claim follows.
