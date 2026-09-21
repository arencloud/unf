# ADR 0396: Matching Kind Configured Shutdown and Traffic

Date: 2026-09-21

Status: scoped configured recovery and reply/inventory gate verified

After ADR 0395's cl02 pass, the independent persistent Kind fleet is upgraded
serially to the identical immutable `6d71a30` controller/agent images. Embedded
revisions, CNI/BPF hashes, CNI STATUS and unchanged Node UIDs pass. All four
retiring regular-container streams complete; three completed installer logs
are retained. The DaemonSet returns to RollingUpdate after serial replacement.

A planned Recreate controller restart and an exact-UID worker-agent replacement
both finish with exit code zero, shutdown request/completion logs, and Ready
zero-restart replacements. Complete Pod watches retain terminal evidence.
This is Native configured recovery, not Required recovery or a loaded deadline.

The expanded gate passes on runtime
`6d71a30984fa130f66c31bbfabdd170a3e63eb59`, qualifier
`f971480c85e129720e4e32c08294db4be1619158`:

- 24 allows (twelve Required, twelve Native), eight unsolicited denials;
  dual-stack TCP/UDP, cross-worker PodIP, Service and translated ports.
- Three CNI UID/nonce bindings and retirements; two candidate replays,
  inventory-count checks and Native retirements.
- 73 WireGuard frames, zero Required plaintext, 89 Native controls and zero
  kernel capture loss on `eth0`. Required and Native convergence each take
  four observations; the fixture Namespace is absent afterward.
- All three fresh ordinary reports converge at policy 35 / Service 19.
  All current runtime Pods are Ready with zero restarts. The existing worker2
  CNI journal is byte-identical; the worker journal is empty. The control-plane
  journal remains absent, independently checked against no non-host-network Pods.

Current regular/init and retained agent CRI logs are reviewed. Both overlapping
message inventories contain 72 warnings, not 144 independent events: 42 plan
sync, 15 proof assistance, four activation and eleven other recovery retries.
There is no ERROR or unknown-key-epoch recurrence. These retries are retained,
not a seamless or resource-efficiency claim.

One retrospective CRI observer races with deletion of the old worker Pod's log
path and fails. Its failure is preserved. The already-open retiring stream
captures that process through successful shutdown; fresh post-recovery and
final CRI reads complete. The failed retrospective observer is not called a pass.

Evidence: `.artifacts/p9-sigterm-6d71a30-kind-*` and
`.artifacts/p9-sigterm-kind-*`. Passing traffic result SHA-256:
`55e1cc5f00845936ce87e139b2340c77d0f160eb8574327d88fd7e02c9578a68`.
Capture SHA-256:
`e165bbd64c8f2f6e198c79c050d7c75deab5fd813c3521a4f546489d3fcfebb9`.

Both live fleets now run `6d71a30`, Native baseline. Candidate `kernelAdmitted`,
`observedDelivery` and `localityAdmission` remain false. Continue authenticated
L3 production consumption, L4/L5 replica/locality and Q full lifecycle, then
S1–S5 stabilization. No release pins or full platform status are promoted.
