# ADR 0372: cl02 Concurrent Target-Peer Movement Gate

Date: 2026-09-14

Status: verified for the bounded isolated foreign-delivery gate; Kind pending

Source `b3c49fb` passes the complete fixture on cl02 using anonymously verified
image `quay.io/arencloud/unf-test-tools-dev@sha256:8f45c6f18fa5e31317cbc1e8035bd2a38fbf120d0e55799799eca0a5aff68a83`.
The diagnostic object SHA-256 is
`966550be9202456e8268e028c1f8c8ba90d1453f50e66af01cfb3566daaf880f`.
All three classifiers load on the RHCOS kernel; concurrent translated/JIT sizes
are 9,696/6,037 bytes. This is not a CPU or throughput improvement measurement.

At 02:06:00 UTC the full serial gate and movement gate pass. All 62 serial
IPv4/IPv6 attempts retain their 28 exact deliveries / 34 denials. Six context
acquisitions and both wrong-context rejections pass without network seeding.
The independent foreign positive control delivers all twenty packets per family
there and none in the original namespace, with counters `[40,40,0]`.

During ten target-peer move/return cycles, both senders complete 20,000 packets
in about 20.08 seconds each. Their 40,000 attempts reconcile to 34,664 redirect
requests and 5,336 classifier rejections. Original-namespace receivers observe
17,288 IPv4 and 17,240 IPv6 unique exact sequences; both foreign receivers
observe zero. Every receiver reports zero socket drops and an empty final queue.
All twenty namespace-specific link snapshots preserve the expected index, full
owner alias and administrative-up state. The source filter uses the concurrent
classifier throughout; no binding/configuration is republished during traffic.

**136 requested redirects have no observed delivery.** They are reported as
unobserved handoffs, not hidden as successful packets or receiver loss. This
bounded gate qualifies absence of foreign delivery with working observers; it
does not qualify lossless handoff or attribute those losses. Follow-up kernel
handoff/address-transition observations remain required before broader claims.

Evidence: `.artifacts/p9-device-lease-b3c49fb-cl02`; raw archive SHA-256
`8d7c192ffa0dad8e0ca88d7bd83b86b51a4e1bbd0d8b718257598a4f6899cee7`.
Independent local replay of the strict gate matches the retained result and
raw per-CPU counters. Private resources and the fixture Namespace are removed;
Node UID is unchanged. The first post-cleanup report is not wholly converged;
a retained final read confirms all five reports fresh/converged at policy 478 /
Service 203. Live runtime remains `f984db9`, all containers Ready, zero restarts.

Controller, every agent and installer logs are reviewed before, during serial
traffic, during concurrent traffic and after cleanup. The final complete window
has 439 bounded flow-history warnings, fourteen proof-assistance retries, three
bounded topology-history warnings and one reciprocal key-attestation publication
rejection, with no live UNF ERROR, panic, OOM or verifier rejection. Existing
warnings and the unobserved handoffs remain open findings.

Matching retained Kind on this exact image is next. This is not source-peer
concurrency, general concurrent lifetime, immutable production publication,
authenticated attachment/address consumption, or Phase 9/S1–S5 closure.
