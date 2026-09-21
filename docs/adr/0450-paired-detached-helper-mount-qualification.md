# ADR 0450: Paired detached helper-mount boundary qualification

## Verified scope

Source `c929d55642d1e1dd574ff4ab38a3d0c2b71731f2` passes the isolated helper-mount
gate on OpenShift cl02, then the identical image on persistent dual-stack Kind:

`quay.io/arencloud/unf-test-tools-dev@sha256:5c3e8ff21780958ea6b6e7b8166ac774aaafc314e1cb28602d3fa3b4940dde40`

Public digest/source-label verification and compiled-source equality pass.
The diagnostic binary SHA-256 is
`3b65081985098922f1e564a4c6ac387bc6f6a4f10d7d07ac696c6b613b66ae06`.

Both gates positively verify real SCM_RIGHTS transfer, helper effective/permitted
capabilities restricted to SYS_ADMIN, client effective/permitted capabilities
restricted to BPF/NET_ADMIN/PERFMON, client mount-namespace creation denied,
actual BPF-map creation/pinning, map-FD survival after mount-handle closure,
eventual pin/map reclamation and unchanged parent mount-namespace identity.
The helper's detached filesystem does not attach to a mount tree. Its exclusive
adapter directory preserves newer kernels' `progs.debug`/other preload entries.

This uses independently capability-restricted test threads inside a disposable
privileged diagnostic, **not separate deployed helper/agent processes or their
final SCC/seccomp profile**. It does not verify packet delivery, authenticated
placement, device seeding, whole-process crash recovery or production integration.
No novelty, performance, unlimited-scale or whole-Phase-9 claim follows.

## Repeatable checks

- `cargo test --workspace`: 921 passed, 34 privileged tests ignored by this local
  invocation. Those ignored tests are not counted as live qualification.
- `cargo test -p unf-locality`: 39 passed, three privileged tests ignored.
- `cargo clippy -p unf-locality --all-targets -- -D warnings`: passed.
- Build `images/LocalityHelperTestContainerfile` from the clean source revision;
  publish/digest-pin and run `hack/verify-locality-incarnation-gate.sh` with
  `UNF_LOCALITY_GATE_SUITE=helper-mount`, explicit source/image/Node UID/context
  and a new evidence directory. Kind requires the matching successful cl02 record.
- Each live run executes exactly one ignored kernel test with the expected
  compiled revision. Both exit zero, restart zero and remove their owned Namespace.

The original `f4c257e` Kind failure and `de05a3c` diagnostic failure remain
retained. They identified kernel-prepopulated bpffs, not a reason to disable
validation. Neither is relabeled as a passed attempt.

## Preservation and complete log review

All five cl02 journals (116 records) and the existing Kind journals are byte-exact
before/after. Kind's empty control-plane journal remains absent. Production Pod
containers remain Ready with zero restarts, so no previous-container log exists
for this window. Current regular/init logs and exact retained/rotated CRI logs
are reviewed on both platforms, with no ERROR, partial/non-JSON observations,
observer error output or capture-limit hit. Warning categories remain unchanged:

| Platform | Current WARNs | Retained WARNs / categories |
| --- | --- | --- |
| cl02 | 473: 433 flow retention, 32 peer proof, six topology retention, two key publication | 14,061 / 23 |
| Kind | Seven peer proof | 93 / 12 |

These warnings remain stabilization work; they are not erased by the helper
pass. Production images remain `45d85d5`. No agent/SCC capability, journal schema,
runtime map, key authority or history was reset or changed for this qualification.

Evidence roots: `.artifacts/p9-helper-mount-c929d55-{cl02,kind}-gate`, matching
`*-journals-{before,after}`, `*-logs-after`, and `*-retained-after` directories.

| Artifact | SHA-256 |
| --- | --- |
| cl02 evidence | `22bb241d358c71168336e790daae36517ebab3af9e93dadc6ddacd15bb6ec253` |
| cl02 test log | `1ace09515f67be009293eeb0f493017f1ea836098ae93a173c381ee62a65af2d` |
| Kind evidence | `e495f194d1f606d723dc438b72d8994724fdbb363b47d514877b84c284d95109` |
| Kind test log | `cbbf98b5235725642a8db98a6e2424aecd903a559d6b81614c4a0072936750c5` |
| Workspace test log | `838d2b265d78fa1b3ee6d5d1a1b01ac57771c0208d5249e83e7ed0fa24380233` |
| cl02 current warnings | `c3f5661cee8b081c50e7cd948c7ed2b8feca1aa6c9c0b720fd9edd76ceb87b6c` |
| cl02 retained warnings | `35e80f133817ee32388ed86d85c9edc086c1b1277d8f214047939b9c77a22daf` |
| Kind current warnings | `1993758b6b09656c65ab9ef2b0f44915a3272124fa34cd3f4cded8ae26552901` |
| Kind retained warnings | `7828f0862fb52f018eaf157cc1b6c08696c5bc1ca1cf27c45b46720f335efd50` |

## Next milestone

Implement trusted separate-process supervision/private endpoint delivery,
peer-instance authentication, a persistent single worker slot and bounded
cancellation/child reaping. Then move descriptor-bound namespace observations
and exact non-transmitting device seeding across that boundary, integrate the
loader/publisher and qualify final deployment/recovery on cl02 before Kind.
The agent must retain its original three capabilities. L3/L4/L5/Q, Phase 9 and
S1–S5 remain open; ADR 0449 tracks each helper sub-milestone independently.
