# ADR 0391: Matching Kind Tombstone and Inventory Qualification

Date: 2026-09-21

Status: scoped gate verified after cl02; full Phase 9 remains open

After ADR 0390 passes cl02, persistent dual-stack Kind runs the same immutable
controller/agent images and CNI/BPF hashes documented there. Runtime is
`8db97bb8029ef21cd053e903cbd4c751d753fd48`; qualifier is
`03364b4c119721d2454c9e8ab673b0dc172e5fb0`. This is the separately approved
three-Node Kubernetes 1.35.0 cluster on host kernel 7.2.5-200.fc44.x86_64, not
continuity with the unavailable historical Kind runtime. No credentials,
release pins, Native baseline or key timing change.

The serial rollout verifies the passing cl02 evidence before mutation,
anonymously pre-pulls exact image digests, retains each retired runtime log,
checks embedded revision, CNI hash and zero-grace STATUS, and restores the
DaemonSet rolling strategy. All Node UIDs and existing CNI records survive.

The complete scoped gate passes 24 allows (twelve Required, twelve Native)
and eight unsolicited reverse denials across IPv4/IPv6 TCP/UDP, cross-Node
PodIP, Service and translated Service ports. Required admission settles on
observation three. The independently stopped capture records 175 WireGuard
frames, zero Required plaintext, 90 Native controls and zero kernel drops.
Three exact CNI UID/nonce bindings retire; both replayed locality candidates
and their actual journal inventory counts retire on Native cleanup.
`kernelAdmitted`, `observedDelivery` and CNI `localityAdmission` remain false.

The fixture Namespace is absent and all three agents converge to Native.
Fresh ordinary reports converge at policy 41 / Service 19. Current runtime
Pods are Ready with zero restarts. The preexisting worker2 attachment journal
is byte-identical. The source worker retains its correctly empty journal
after first use; the control-plane journal remains absent with independently
checked absence of non-host-network Pods. No journal is deleted or reset.

Current and retained CRI logs are reviewed before and after validation; the
final regular/init-window review and retained agent CRI review agree on 41
warnings: 22 plan-sync, eleven path-proof assistance, five pending activation,
two transient TC attachment and one startup fleet fence. No ERROR or unknown
key epoch is observed. Retry warnings are retained, not presented as clean
logs. The separate SIGTERM defect from ADR 0390 remains open.

Evidence: `.artifacts/p9-retired-8db97bb-kind-*` and
`.artifacts/p9-retired-kind-*`. Result SHA-256:
`94d7f440397d28cb9c1dc3ce459241a47156313455684810528cf63f4aba06e0`.
Capture SHA-256:
`481a79673c792ce78009dcf17f5f9cbf905db0e48fb81219692569f6ba0263ac`.
This closes the scoped repair/inventory qualification, not authenticated
production locality consumption, L4/L5 replica coverage, Q lifecycle or S1–S5.
