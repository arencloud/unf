# ADR 0373: Matching Kind Concurrent Target-Peer Movement Gate

Date: 2026-09-14

Status: verified for the bounded isolated foreign-delivery gate

After cl02's ADR 0372 pass, retained Kind passes the identical source `b3c49fb`
image `quay.io/arencloud/unf-test-tools-dev@sha256:8f45c6f18fa5e31317cbc1e8035bd2a38fbf120d0e55799799eca0a5aff68a83`.
The imported manifest/digest reference is checked. Diagnostic object SHA-256
remains `966550be9202456e8268e028c1f8c8ba90d1453f50e66af01cfb3566daaf880f`.

At 02:12:04 UTC the complete serial/context and concurrent gates pass. All 62
serial attempts retain 28 exact deliveries / 34 denials; six context acquisitions
and two rejected contexts pass. The independent foreign positive control delivers
twenty packets per family there, none in the original namespace, with exact
`[40,40,0]` counters and functioning socket-loss accounting.

Both 20,000-packet senders finish in about twenty seconds during ten target-peer
move/return cycles. Original receivers observe 17,651 IPv4 and 17,655 IPv6 unique
sequences; both foreign receivers observe zero. Every receiver has zero socket
drops and an empty final queue. The 40,000 attempts reconcile to 35,349 redirect
requests and 4,651 classifier rejections; all twenty link snapshots pass.
Concurrent translated/JIT sizes are 9,696/6,059 bytes, not a performance result.

**43 redirect requests have no observed delivery.** Like cl02's 136, these remain
explicit unattributed handoffs, not successful delivery or receiver loss. The
fixture currently brings a moved peer up before restoring addresses/routes;
that ordering is a hypothesis to investigate, not an attributed cause. Neither
bounded pass proves lossless handoff or full concurrent lifetime.

Evidence: `.artifacts/p9-device-lease-b3c49fb-kind`; raw archive SHA-256
`f340ebb4b923d165dea4400c47c5ab8b7a6cf8c07aa1be3386dcdb4df2310d56`.
Independent gate/per-CPU replay matches the retained result. Private resources
and the fixture Namespace are removed, Node UID preserved. All three reports
finish fresh/converged at policy 63 / Service 19. Regular containers are Ready
with zero restarts; init installers are completed. Live runtime stays `f984db9`.

Before/during/after controller, every agent and installer logs are reviewed.
The final current window has no WARN/ERROR; retained current/rotated agent CRI
logs contain older proof/activation retries (231,336 lines / 136,978,468 decoded
bytes). No live UNF ERROR, panic, OOM or verifier rejection is observed. INFO
volume and previously recorded retries remain stabilization findings.

Both platforms pass the bounded foreign-delivery experiment. Next, investigate
device-map references for all four veth endpoints so peer movement invalidates
the lease until explicit rebind, including a move-and-return between userspace
observations. Source concurrency, immutable publication, live attachment/address
authentication, consuming composition and full Phase 9/S1–S5 remain open.
