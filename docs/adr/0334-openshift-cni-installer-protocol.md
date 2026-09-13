# ADR 0334: Isolated OpenShift CNI Installer Protocol Qualification

Date: 2026-09-13

Status: isolated cl02 packaging slice verified; matching Kind pending

The three real-executable integration tests from ADR 0333 pass on cl02's
RHCOS worker `bc-24-11-27-b6-49`, preserving Node UID
`1ade5ebe-7f24-4f35-b9d4-aca5b13b1c2b`. Source revision:
`e6fc6587df65d54a91c0d55d7f3a3512b43dea43`. Anonymous registry inspection
confirms the same OCI revision on
`quay.io/arencloud/unf-test-tools-dev@sha256:b048b6223ae2cc5b72edc32023a3928ba55b7bc8cd9ff455ba3a931343ce6aef`.

SHA-256 evidence:

- Production CNI: `d7a6c83d06b237942b076ee264aaab6bd5f3bbb1955ba210db7ff827b33f8781`.
- Compiled packaging tests: `4c8bab4a8cebc141860ca763261aa17b55c7abb77e29d95d2f19d9e596e6b819`.
- Complete result log: `4e464577c2ec37b2844a3804edbed3bf5dbd0bd1de189c020046a0a73724dea2`.

All three tests pass without ignored/filtered cases. The production executable
must exchange current STATUS with fixture peers before the real installer
replaces fixture artifacts. Old/malformed responses, stale socket with fresh
lease and invalid wait settings are refused; successful initial installation
and candidate upgrade preserve the intended ownership transaction semantics.
Paths are remapped only into private temporary fixture directories. This does
not exercise the live agent socket, host filesystem labels or a live CNI rollout.

The zero-restart, tokenless test Pod has no host mounts, drops all capabilities,
disallows privilege escalation, uses a read-only root filesystem and writes only
its bounded temporary volume. It is not privileged; the observed admission SCC
is `node-exporter`. Its owned namespace is removed and absence checked.
Live UNF containers remain Ready with zero restarts; neither image fleet changes.

Controller, every agent and installer logs are retained before/during/after.
The final 20-minute window contains 392 bounded flow-history warnings, 23
peer-proof-assistance warnings, four bounded topology-history warnings and
three rejected key publications. The collection is 429 lines / 102,998 bytes;
no file reaches its tail/byte cap. No ERROR/panic/OOM/verifier rejection or
stopped-dataplane match is found. Warnings remain operational stabilization
findings and are not suppressed or treated as clean-history evidence.

Matching-image Kind is next after this result is committed and pushed.
Kind live upgrade ordering, new CNI/runtime rollout and actual locality
consumption remain open, as do L4/L5/Q and stabilization S1–S5.
