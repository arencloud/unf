# ADR 0447: Locality runtime candidate publication

Date: 2026-09-21

Status: immutable development images published; not deployed or runtime-qualified

Built from clean source `762c9809b25ac95961b51469f3973ba809892ac8`, the development
images are publicly pullable at these immutable references:

- Controller: `quay.io/arencloud/unf-controller-dev@sha256:8858f66d310f49342819791c489c17fb824658e5ca4f7b295f84c2d4c621e144`
- Agent/CNI: `quay.io/arencloud/unf-agent-dev@sha256:e5cb4346950562b307f96b6e1c89f4ca5013be7d1bc5db06297e03ffdd17e34c`

Public registry reads without credentials confirm both digests and source
labels. The main ELF is byte-identical to ADR 0446's paired diagnostic; the
sealed bank is copied from the same immutable, separately qualified base, not
rebuilt into an untested replacement.

| Agent-image component | SHA-256 |
| --- | --- |
| Agent executable | `42ab0ce9371bdbb78ee2650c59395afb5adcd41632ff1ce062c3a8d5c03f1bf6` |
| CNI executable | `0d210ddb084584fef92d83819a2f484baab0203d54a93dfcb3565ac816203faa` |
| Main ELF | `eaea640f23f6134ed96363e970979d6d1c340c75dc237fab93852f1cdd37774d` |
| Locality bank ELF | `93da80e50201d45841b1253d489328518bdc5f593518f9329d6e9345dca0faa3` |

No release pins or production workloads are updated. These image labels/hashes
are not a substituted live `/v1/version`, shutdown, rollout, packet or recovery
result. Existing production remains `45d85d5` on both fleets. The ignored rollout
helper refuses execution without an explicit approval marker, the actual desired
SYS_ADMIN/SCC checks, paired diagnostic evidence and the still-pending isolated
runtime shutdown/version gate. It has not been run.

ADR 0445's privilege-boundary choice remains required before cl02 rollout.
After resolution, qualify the exact chosen runtime configuration on cl02 first;
only then advance the matching Kind runtime. Preserve old journals and their
normal schema-5 reader-floor migration; no reset or unsafe downgrade.

Evidence: `.artifacts/p9-locality-runtime-762c980-*`, including public registry
metadata, input/executable hashes and the complete build/push log. Registry
authentication remains in the existing ignored private credential file and
is not included in Git.
