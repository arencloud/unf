# ADR 0335: Matching Kind CNI Installer Protocol Qualification

Date: 2026-09-13

Status: isolated OpenShift packaging slice verified on cl02, then Kind

After ADR 0334 is committed and pushed, retained Kind passes all three
production-CNI/installer integration tests using the identical immutable image:
`quay.io/arencloud/unf-test-tools-dev@sha256:b048b6223ae2cc5b72edc32023a3928ba55b7bc8cd9ff455ba3a931343ce6aef`.
The imported archive manifest matches the published digest. Source revision is
`e6fc6587df65d54a91c0d55d7f3a3512b43dea43`; CNI and compiled-test SHA-256 values
match ADR 0334. Independent Kind result-log SHA-256:
`5fc57125cd560cacd70b9bc25c5ab28ed5a2460d4b7b54c64111318d5ae626e5`.

The exact worker UID remains `c5c2bc2c-b272-46b5-943e-c81418307749`. The
non-privileged, capability-free, tokenless test Pod has a read-only root and
bounded temporary volume, no host mounts and zero restarts. The owned namespace
is positively absent after cleanup. No live installer, image or journal changes.

Controller, every agent and installer logs are retained around the run. The
expanded preflight collects 48,151 lines / 26,625,859 bytes, all files below the
16-MiB per-file limit. Current logs rotate during validation, shortening later
API reads. Retained current/rotated CRI readback therefore collects 184,703
lines / 109,128,909 bytes. It includes one current proof-assistance warning,
alongside older warnings (18 total proof-assistance, six activation, four plan
synchronization, one egress synchronization and one flow export). No observed
ERROR/panic/OOM/verifier rejection or stopped-dataplane match is found.
All live UNF containers remain Ready with zero restarts. Rotation and log
amplification remain explicit S1/S3 findings; this is not all-time log coverage.

This verifies the OpenShift packaging guard on both kernels, not the separate
Kind init-installer topology or a live runtime upgrade. The next boundary is
state-preserving live CNI rollout and genuine runtime UID capture, followed by
authenticated locality consumption. Live fleets remain `67c2772`; L3, L4/L5/Q
and S1–S5 remain open. No full Phase 9 platform row is reverified here.
