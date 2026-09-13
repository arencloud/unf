# ADR 0303: Fail-Closed Build and Deployment Provenance

Date: 2026-09-13

Status: repair implemented; rebuilt cl02-first qualification pending

The ADR 0302 Native gate stopped at preflight: `/v1/version` reported `b5bf6c6`
although the image was built from source `64ad559`. Inspecting the reused and
new builder layers confirmed `UNF_BUILD_REVISION=b5bf6c6`. An inherited `ENV`
with the same name took precedence over the Containerfile `ARG`; compilation
included the new source but stamped the wrong provenance. Keep those immutable
images and failed evidence as rejected candidates, not qualified runtimes.

Use the distinct build input `UNF_SOURCE_REVISION` to set the compiler's
`UNF_BUILD_REVISION` environment. Update all current build entry points; the
historical baseline builder detects which argument its archived Containerfile
supports. The Makefile's user-facing `UNF_BUILD_REVISION` variable is unchanged.

The staged deployment also falsely accepted the mismatch. Bash disables
`errexit` in a function invoked as a conditional; subsequent successful egress
and encryption checks masked the initial failed version/ABI predicate. Each
predicate now explicitly returns failure. The regression extracts the actual
production function and calls it conditionally, rejecting missing, null and
wrong values for every checked field, malformed responses, and wrong revisions
with optional feature checks disabled. It failed against the previous script
and passes with the repair. The Phase 9 OpenShift local gate runs this test.

The live failed preflight is retained in ignored
`.artifacts/s1-native-keys-64ad559-native-cl02/`. It created no traffic fixture;
Kind remains at its original mixed-cursor state. Rebuild immutable images,
verify the embedded versions before deployment, then repeat the corrected
staged deployment and Native adoption/packet gate on cl02 before Kind.

This is qualification hardening, not completion of Phase 9 or evidence of
heavy-load stability, lower CPU/memory use, or a supported scaling envelope.

Rebuild source: `54f55112e37bb91c35e46683b4bf32533bd4294d`. The corrected
builder layer's compiler environment matches this hash, and both final images
report it through their version APIs when run locally, read-only, unprivileged,
without cluster credentials or BPF access (controller offline; agent without a
controller or interfaces). These checks are provenance checks, not platform
feature qualification. The full Phase 9 OpenShift local gate also passes.

| Component | Immutable Quay manifest SHA-256 |
|---|---|
| controller | `82a0196b9ce4bbb2ea890bf34adee7ae762418946a11365a29427b7996fd57fa` |
| agent | `b5713aa56fed25cb1a21c65c8ca8a8a30e0de73cf85d245a5e10eb28b730eb2c` |

The development tag is `s1-provenance-54f5511`. Test tools are unchanged.
Release pins retain `openshift-first` and pending Kind evidence. Build, push
and local version observations remain in ignored
`.artifacts/s1-provenance-54f5511-*`.
