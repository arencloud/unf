# ADR 0277: Bounded checkpoint codec fallback

Date: 2026-09-12

Status: Implemented; cl02 transition and recovery qualification pending

## Context

Three cl02 candidates exposed a transient recovery gap: a combined frontier and
fleet plan exceeded the existing 900,000-byte stored-data bound during Required
transitions, although later cuts fit. The most recent failure required 911,814
bytes and recorded 35 failed writes before a smaller cut persisted. Splitting
frontier and plan into independent mutable objects would tear recovery.

Tests of all nine levels in the existing gzip backend did not supply useful
headroom. The fallback below is a storage-only use of a standard codec, not a
new cryptographic algorithm or an unsupported performance claim.

## Decision and bounds

Retain byte-compatible schema-v1 gzip writes whenever the complete descriptor
and payload fit the original bound. Otherwise discard that compressed buffer
and try single-threaded Zstandard level 3, with an explicit 2-MiB window and
frame checksum, using a schema-v2 descriptor with codec `zstd`. If that complete
representation still exceeds the bound, refuse it and retain the last durable
checkpoint. No storage, decoded-size or authority limit is raised.

Both encodings contain the unchanged schema-v1 envelope and remain one atomic
ConfigMap update. The existing `checkpoint.gz` key is retained as a legacy
opaque payload key; readers must select the codec from `checkpoint.json`, not
from the suffix. The descriptor binds both lengths and both SHA-256 digests.
Restore accepts only `(1, gzip)` and `(2, zstd)`, rejects oversized stored input
before decoding, limits output to the declared length plus one byte under the
unchanged 64-MB ceiling, and rejects a zstd window larger than 2 MiB or trailing
frames/data. Existing semantic frontier/plan validation still runs afterward.

The locked `zstd` dependency disables optional default features and uses its
bundled native implementation with no parallel compression workers. The local
controller binary has no dynamic libzstd dependency; release image linkage must
also be checked. See the [Rust decoder interface](https://docs.rs/zstd/0.13.3/zstd/stream/read/struct.Decoder.html)
and upstream [memory-bound guidance](https://github.com/facebook/zstd/wiki/Using-libzstd-in-a-memory-constrained-environment).

## Upgrade and rollback boundary

New readers retain legacy JSON and schema-v1 gzip recovery. Old readers reject
the v2 descriptor rather than resetting state or treating it as gzip. Fallback
is used only when the old representation already exceeds its supported bound;
this does not make an oversized cut supportable by an older runtime.

Before a downgrade to a gzip-only controller, use the current controller to
produce and verify a schema-v1/gzip checkpoint within its bound. If the checkpoint
remains v2, keep the compatible controller or plan an explicitly approved
workload/intent reduction; do not delete the checkpoint, raise its bound or
silently disable Required encryption to force a rollback. A smaller compatible
cut automatically returns to gzip on the next successful write. Read-only check:

```sh
oc -n unf-system get configmap unf-encryption-generation-frontier -o json |
  jq -e '.data["checkpoint.json"] | fromjson | .schemaVersion == 1 and .codec == "gzip"'
```

## Verification

The compact-store regression proves the unchanged gzip path, forced fallback
under a smaller test budget, identical restored frontier/plan and payload
digest, refusal when neither encoding fits, exact codec/version pairs, bounded
expansion, corruption rejection, concatenated-frame rejection and rejection of
a valid-envelope frame requesting a larger decoder window.

An ignored reproducible diagnostic using the public cl02 capture round-tripped
all typed invariants: 22,164,122 decoded bytes became 791,134 gzip bytes or
336,656 bounded-zstd bytes. Its debug timing includes repeated complete semantic
replay and is not a production CPU benchmark. The exact transient overflowing
cut was not captured; cl02 must still prove successful transition persistence,
controller replacement and return to compatible gzip, followed by fresh Kind.
This change creates headroom, not unlimited capacity or heavy-load readiness.
