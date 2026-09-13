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
