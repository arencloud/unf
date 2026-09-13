# ADR 0302: Key-Independent Native Candidate Qualification

Date: 2026-09-13

Status: candidate rejected by Native preflight; superseded by ADR 0303 provenance repair

Source `64ad5599bbb21ecdbf0c859d7090f16714a33f96` includes exact
predecessor-receipt recovery (ADR 0298) and wholly Native key-readiness isolation
(ADR 0300). Its 745 workspace tests, 25 explicit environment-dependent ignores,
formatting and strict all-target/all-feature Clippy checks are recorded in
ADR 0300. The qualifier now also requires exact fixture adoption (ADR 0301).

| Component | Anonymous Quay manifest SHA-256 |
|---|---|
| controller | `1e25fc09653c09b453b4430a620ae1ffb94d9d67512f85a725488d5774379d65` |
| agent | `f4dc74b43790ea2dede118aab64294d23b9a992b5355d1d5b6909f34f685b59f` |
| test tools, unchanged | `e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352` |

Controller and agent use development tag `s1-native-keys-64ad559`; release
manifests pin the digests, not the tags. Public manifest hashes match the push
results. Build logs remain under ignored `.artifacts/s1-native-keys-64ad559-*`.
The original Containerfile is unchanged. Its Rust base argument reuses the
previous compiler/cache layer
`a65a90027d74bb7f079b59b94f4ef98b378da8ae8cad988236e987d90a9b7b61`,
which was built from the same Rust 1.95 toolchain for `b5bf6c6`. Current sources
were copied and `cargo build --locked --release` ran, but subsequent live
preflight found that the inherited builder environment overrode the requested
revision: the binaries report `b5bf6c6`, not `64ad559`. The image digests remain
correct, but their asserted embedded source provenance is invalid. The staged
deployment's conditional shell check masked this mismatch (ADR 0303). Its
success must not be counted as runtime-version verification. No Native traffic
fixture ran for this candidate and it was not deployed to retained Kind.

Deploy cl02 controller-first/node-serially, verify runtime versions and the
expanded Native packet gate, then recover the retained Kind cluster without
clearing its original partial frontier or journals. The release record keeps
`openshift-first` and pending Kind evidence. ADR 0299's failed run is retained;
no new runtime is qualified by the older `571379d` pass.

Phase 9 remains open pending these results, fresh-Kind/full lifecycle coverage,
Required locality/replica/reply work and continuity checks. S1–S5 remain open;
no heavy-load capacity or resource improvement is asserted from these images.
