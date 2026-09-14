# ADR 0381: cl02 Joint Native Attachment/Route Observation Gate

Date: 2026-09-14

Status: verified for the isolated joint snapshot API; matching Kind pending

Source `91cc771` passes the complete cl02 gate on anonymously verified image
`quay.io/arencloud/unf-test-tools-dev@sha256:9f519400e453bd4bb704a91ba2a83f6b747681830f4dba33ff2f982b83af65bd`.
At 03:52:07 UTC all 28 ordered observations pass: ten positives, six exact
route/neighbor drift rejections, two path/link drift rejections, one cancelled
recheck and nine sticky-retirement checks.

Removing each IPv4/IPv6 host workload route or peer default route is rejected
with the exact namespace and missing-route count. Host IPv4 and peer IPv6
neighbor removal similarly produces the exact missing-neighbor count. A bind
mount replacing the peer namespace pathname is rejected by descriptor identity;
MTU drift is rejected by the strict link readback. Restoring each fault leaves
the old joint observation retired. Explicit fresh observation succeeds.

Cancelling a recheck at its first pending poll leaves both readback and retained
namespace-descriptor access unavailable. A later recheck stays rejected; fresh
construction succeeds. The qualifier also checks descriptor/readback presence
on success and absence after every failure. These are snapshot lifecycle tests,
not packet-time locality permission or an atomic multi-resource transaction.

Evidence: `.artifacts/p9-native-attachment-91cc771-cl02`; archive SHA-256
`d876bfe09352ea08289d172a05e296469b3a264d69436197128e1a1420421aa6`.
Individual results, exact error roles/counts, observer stderr and cleanup are
reviewed. The private namespaces and Kubernetes fixture Namespace are removed;
Node UID is unchanged. All five live reports finish fresh/converged at policy
504 / Service 203. UNF containers remain Ready with zero restarts on `f984db9`.

Controller, every agent and installer logs are read before/during/after. No
observer failure or byte cap occurs. The final window retains 434 bounded-flow,
13 proof-assistance, two key-publication and two bounded-topology warnings,
with no ERROR entries. Existing reliability/resource findings remain open.

Matching retained Kind on this exact image is next. The supplied fixture record
is synthetic; joining actual CNI journal state to authenticated current placement,
scale-efficient inventory, immutable packet consumption and full Phase 9/S1–S5
remain open. No live caller or packet permission is switched by this gate.
