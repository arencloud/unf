# ADR 0439: Paired publisher/main-hook socket qualification

Date: 2026-09-21

Status: verified private-network composition; fleet/recovery closure remains open

The complete `807a130` diagnostic passes cl02 first, then persistent Kind on
the identical immutable image:

`quay.io/arencloud/unf-test-tools-dev@sha256:7154ebd2d3d9d949bb643d6f64daa7f2c20c9248ba6d95f9c93135e580c7ac1a`

On each platform the seven-test main-program suite passes before the two-test
publisher/socket suite. Compiled source equality is positively checked in both.
The test binary SHA-256 is
`de41bf0b6cf8b176bb15df1794d252ce565822184b6864e3982ade7b80757132`;
main ELF SHA-256 is
`2bdcd744e74b66e7cd28dd6eb323f32cc6ee4f220a3e2566495bf001722668ac`.
The packaged bank remains the immutable, separately qualified base component
documented in ADR 0437.

The real journal-bound publisher observes, seals, publishes and reuses its bank
against exclusively owned maps loaded by the actual main classifier. Both
directions traverse that classifier and the selected bank. Actual 1,200-byte
TCP/UDP application payloads and replies pass for IPv4/IPv6 PodIP and translated
Service ports. No ordinary Native transport decision exists to mask a bank miss.

Each platform passes sixteen positive exchanges and twenty expected denials:
unpublished state, pending writer, completed writer without republication,
policy-denied Service requests, and retired source while its links still exist.
Fresh republication and policy restoration recover delivery. Unique source
ports prevent earlier established flows from satisfying later denial tests.
The cl02 socket test takes 43.51 seconds; Kind takes 41.40 seconds, mostly the
intentional denial timeouts. These are test durations, not throughput results.

Exact private link/bpffs inventories, private namespace identities/removal and
outer Kubernetes namespace cleanup pass. All gate processes exit zero without
restarts. Production remains `45d85d5` on both fleets, Ready/zero restarts, with
byte-identical journals and Kind's empty control-plane journal still absent.
No production image, map, key, journal or history was reset.

Current and retained/rotated regular/init logs are reviewed on both platforms,
including controllers. No ERROR, observer failures or incomplete JSON records
are found. cl02 has 464 current WARNs (421 flow retention, 34 peer-proof, eight
topology retention and one key-publication retry), and 7,395 retained WARNs in
22 known categories. Kind has five current peer-proof WARNs and 75 retained
WARNs in twelve categories. These remain findings, not a stability claim.

Evidence roots: `.artifacts/p9-kernel-main-{bridge,composition}-807a130-{cl02,kind}`
and `.artifacts/p9-main-807a130-*`.

| Artifact | SHA-256 |
| --- | --- |
| cl02 main result | `13c3ad4da9f45dbbdf1e18bada771014dc3130906e8b332a6e2b174a385aabac` |
| cl02 main log | `8a27f5844e153f230f32dd90efe49fef6f2166d6badb67b6fa37df0822071f60` |
| cl02 socket result | `f0c33d2a8e4357c99ce6280f267587cf8f04187bbc03741c1e86b5115f792374` |
| cl02 socket log | `2eac8727fdd7e61945a6e163895fa4a277cf309acfee6266e3b2da0c2df9b164` |
| Kind main result | `b17470097899145d8ea1f7646ffdd7a7b5d56c78abfca4d226c364f9ec2486d7` |
| Kind main log | `1028f563ec8a6bb6cc53ccb9507087bbffbb619ba8d8ef9167712dcf7fd73862` |
| Kind socket result | `0a438fe57fb1e9dccfb3c1e2fbbc6b8d5dd2d7e970b9c9fecda6f24c06052252` |
| Kind socket log | `b3ab3fa06d97d7407520b8ca6e74198ed569204812072eb364e0733ffaadf358` |

This closes the bounded real-publisher/main-hook/socket composition gate, not
authenticated controller distribution, complete production reconcilers, DSR
sockets, cross-worker Required ciphertext, mixed replicas or restart recovery.
L3/L4/L5/Q and S1–S5 remain open. Restart continuity is next; restored metadata
must never directly restore bank, device or packet authority.
