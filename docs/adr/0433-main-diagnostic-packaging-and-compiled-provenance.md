# ADR 0433: Main diagnostic packaging and compiled provenance

Date: 2026-09-21

Status: packaging repair implemented; rebuilt platform gate pending

The `843d810` main-program diagnostic build failed at its final script COPY:
`.containerignore` excluded the new script. No image was published and no
platform test or runtime rollout used that attempt. The failure is retained in
`.artifacts/p9-main-locality-843d810-build.log`. The allowlist now includes the
exact script **after** the general `hack/*` exclusion.

Review also found an old revision in a reused intermediate builder layer's
configuration metadata. Direct inspection of the resulting `5f03031` startup
binary instead found the correct full `5f030319526bb534bf73c64cac1b04378907a972`
revision, not that old value. Thus there is no demonstrated mislabeled binary
and ADR 0431's behavioral results remain valid. Intermediate metadata is not
sufficient evidence of the compiler's effective environment.

The production and diagnostic build commands now explicitly export the revision
from the distinct source ARG in the same RUN as compilation. The main diagnostic
also runs an exact test comparing the compiled `BUILD_REVISION` with an externally
provided full source revision. The gate requires that value, supplies it to the
Pod and records it in evidence. Five exact tests must execute, including that
positive provenance assertion; an empty filtered test list cannot pass.

Local test compilation, strict agent all-target Clippy and shell syntax checks
are required. The rebuilt immutable main-program gate must still pass cl02 first,
then matching Kind. Pending reverse-Service edits are separate from this repair
and must not enter its source/ELF provenance. No production state changed.
