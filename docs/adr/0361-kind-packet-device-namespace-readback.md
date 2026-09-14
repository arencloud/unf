# ADR 0361: Matching Kind Packet-Time Device/Peer Namespace Readback

Date: 2026-09-14

Status: verified for the isolated drop-only readback primitive

Following ADR 0359's corrected cl02 pass, retained Kind passes the identical
source `03984e9` fixture image:
`quay.io/arencloud/unf-test-tools-dev@sha256:6ca231f6a4b26674bb16caa57eea671388150e884182e57b1aa5a8d30ee46ade`.
The image's source label and imported manifest digest are checked independently.
The separate diagnostic BPF object's SHA-256 remains
`f49e36ee72db18521455de2a008c4babbd7f26c5d1d0c7b470f54d8efe7d07e9`.
The failed first Kind metadata gate remains recorded in ADR 0360.

Kind's running-kernel BTF resolves byte offsets 16/224/264/4608/2752 for
skb device, device index, device namespace, namespace cookie and private peer.
Equivalent split-module definitions pass the bounded agreement check. The
kernel accepts the unchanged 3,304-byte translated classifier; the JIT body is
2,187 bytes on this kernel. Program size is not a throughput/resource benchmark.

At 00:25:13 UTC all nine observations and one invalid-configuration rejection
pass: IPv4/IPv6 baseline, peer namespace move/return, host rename and restored
configuration. Exact packet counters, current interface indices and independent
socket-cookie bytes are checked. Invalid configuration retains no stale identity
fields. Every packet is dropped; no live UNF interface, map or runtime is changed.

Evidence: `.artifacts/p9-device-observation-03984e9-kind`; raw archive SHA-256
`3f663e23c2c68b639031229ac615cfd6f74561d797f31127a660ee55a96f4edc`.
Private namespaces/attachments/bpffs and the Kubernetes fixture Namespace are
removed. The Node UID is preserved. All regular UNF containers remain Ready
with zero restarts; all three init installers remain successfully completed.
All three reports finish fresh/converged at policy 52 / Service 19.

Controller, every agent and installer logs are reviewed before and after, with
the final window covering the run and cleanup. Retained current/rotated agent
CRI logs are also read: 274,882 lines / 162,952,531 decoded bytes, including
older history. They contain fourteen proof-assistance warnings, six activation
queue warnings and three pending-activation warnings; no live UNF ERROR, panic,
OOM or verifier failure is observed. Their large INFO volume remains a concrete
S3 stabilization lead, not evidence of low resource consumption.

Both kernels now qualify this isolated packet-time readback mechanism. It does
not establish continuous safe delivery, authenticated source/target ownership,
banked publication or post-policy/Service/egress locality consumption. The flags
`kernelAdmitted` and `observedDelivery` remain false. Full Phase 9 and S1–S5 stay
open; the next L3 work must bind actual device observations to attachment
ownership and a lifetime-safe delivery path before any plaintext exception.
