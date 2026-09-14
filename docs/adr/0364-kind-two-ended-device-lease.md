# ADR 0364: Matching Kind Two-Ended Device Lease Delivery Gate

Date: 2026-09-14

Status: verified for the isolated serial delivery mechanism

After ADR 0363's corrected cl02 pass, retained Kind passes the identical
source `5f553c3` fixture image:
`quay.io/arencloud/unf-test-tools-dev@sha256:0a8dffc8dca0edbf1f24ef8425e579aeb94b485f73a23414a1fdf033f9e0962a`.
The imported manifest digest is checked against the public image. Diagnostic
object SHA-256 remains
`e0f7381b1bd9b729c678ffb507e640bee3a28af8b37f2e7b4102af7db1176037`.

The complete IPv4/IPv6 matrix finishes at 00:49:24 UTC: sixteen exact application
deliveries, fourteen ready-receiver timeout denials, thirty matched attempt
counters, eighteen requested redirects and twelve classifier rejections. The
same rename, source/target peer movement, peer down/up, host move/return,
deletion/index/MAC reuse, explicit rebind and configuration cases pass. Moving
or deleting the target host invalidates the device-map binding; reappearance
does not implicitly restore it. Pointer reseeding is explicit and serial.

Receiver RPF settings remain 0/2 with declared reverse routes; no RPF sysctl
changes are made. Kernel translated/JIT program sizes are 5,288/3,390 bytes
for redirect and 3,272/2,086 for seed. These are not CPU/throughput measurements.

Evidence: `.artifacts/p9-device-lease-5f553c3-kind`; raw archive SHA-256
`c601ec0d9a0d10c246ef83634d81f41ea98c405d3d0081cf7e04a8894df48200`.
All private fixture resources and the Kubernetes Namespace are removed, and
Node UID is preserved. Regular UNF containers remain Ready with zero restarts;
all three init installers remain successfully completed. All three reports
finish fresh/converged at policy 54 / Service 19. Live runtime stays `f984db9`.

Before/final controller, every agent and installer logs are reviewed, with the
final window covering the run and cleanup. Current/rotated agent CRI readback
contains 278,159 lines / 164,858,763 decoded bytes, including older history.
One proof-assistance warning is in the current window; older retained CRI
also contains proof and activation retries. No live UNF ERROR, panic, OOM or
verifier rejection is observed. INFO amplification remains an S3 finding.

Both kernels qualify the isolated serial delivery/invalidation mechanism, not
authenticated production locality authority or a concurrent lifetime guarantee.
CNI address/UID/nonce binding, administrative-down semantics, immutable bank
publication/retirement, concurrent movement and policy/Service/egress composition
remain open. No live plaintext exception is enabled. Full Phase 9 and S1–S5
remain open; these bounded results do not reverify either full platform row.
