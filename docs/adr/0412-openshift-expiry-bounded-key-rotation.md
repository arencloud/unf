# ADR 0412: cl02 Expiry-Bounded Rotation, Recovery and Traffic

Date: 2026-09-21

Status: scoped cl02 runtime qualification verified; matching Kind pending

ADRs 0409 and 0411 now pass the current-runtime cl02 gate on source
`45d85d5762d3340c1c64bdefcffef21071d8334f`. ADR 0410's failed predecessor
attempt remains retained. No key, journal, map, history or baseline reset is
used to obtain this result.

## Immutable runtime

- Controller: `quay.io/arencloud/unf-controller-dev@sha256:ae05bc9ca1e3c6741378103c2748d1dd9ca3734412d8f3922b1eb7ef19354ed4`.
- Agent/CNI: `quay.io/arencloud/unf-agent-dev@sha256:74f80c81d5a208dcfe8904ca406ca174e35a1bdeccb04ebfcecd856a13938a45`.
- CNI SHA-256: `4825143419c747fb76d0c486fc3edb94ba06adb0af05e8e4c5c214b6a7f3b01c`.
- Unchanged BPF SHA-256: `d8551daad5f6222a8b9ddd7b3e7ed5d869bdea53c99b1e8c692f8ec0c205a27d`.

Public registry digests/labels, embedded versions, all five installed CNI
binaries and zero-grace CNI STATUS pass. All eleven retiring regular-container
log streams finish successfully. Four isolated PID-1 SIGTERM/SIGINT tests exit
zero without restarts and remove their owned Namespace. A subsequent configured
controller Recreate restart and exact-UID worker-agent replacement both record
shutdown request/completion and terminal exit zero, followed by Ready,
zero-restart replacements. This is Native planned recovery, not Required-mode
recovery or a loaded shutdown deadline.

## Observed result

All five current agents record successive activations 6480, 6481, 6482 and 6483.
Logs also record transport-free predecessor retirement and exact transport
retirement for epochs 6480–6482. The authenticated bootstrap, round and complete
reciprocal cut return HTTP 200; the captured cut contains all five epoch-6480
proposals. Neither sealed-expiry drain rejection nor unknown-epoch failure
recurs in the reviewed candidate logs.

The complete expanded scoped reply gate passes:

- 24 allows (twelve Required, twelve Native) and eight unsolicited denials;
  IPv4/IPv6 TCP/UDP across workers, PodIP, Service and translated ports.
- Three actual CNI UID/nonce bindings and retirements; two locality-candidate
  replays and retirements, with real journal-inventory counts.
- `br-ex` capture: 247 WireGuard frames, zero Required plaintext, 74 Native
  controls and zero kernel capture drops.
- Required convergence at observation 16; Native cleanup at observation 18.
  Namespace absent, all five Nodes Native and fresh ordinary reports converged
  at policy 352 / Service 193 in the final controller incarnation.
- All 116 pre-existing CNI records remain byte-identical after rollout,
  configured recovery and fixture cleanup. No legacy attachment is rebound.

The capture-container lifetime includes waiting for the traffic marker; it is
not the packet-capture interval. No seamless rotation, latency or scale claim
is inferred from eventual convergence.

## Log audit and remaining scope

Current regular/init logs, configured-recovery retired streams, upgrade streams
and exact retained kubelet CRI files are reviewed. Current logs contain 1,292
WARNs across 21 categories, no ERROR, no observation error and no byte-cap hit.
The overlapping later CRI inventory has 1,296 WARNs, no ERROR, partial line or
non-JSON record; these are not additive event counts.

Warnings retain controller-restart connection/503 bursts, 261 existing-clsact
messages, 162 proof-assistance retries, 154 bounded flow-history messages,
exact-generation receipt mismatches, one probe rendezvous timeout and four
locality-candidate 503s. All 87 current key-publication warnings are confined to
the planned controller restart, not recurring activation failures. Existing
oversized-ipBlock and conflicting named-port admissions remain visible.
One staged controller operations-persistence retry still lacks its root cause;
later durable progress does not close that logging defect. S1 must address
retry amplification and convergence costs rather than relabel them harmless.

Evidence: `.artifacts/p9-drain-expiry-45d85d5-cl02-*` and
`.artifacts/p9-drain-expiry-cl02-*`, including public-only progress samples.
Passing traffic evidence SHA-256:
`ffc8487b27b171f32a93f66961e8c4aa2936ccea5a776dd135a39cd8fb352614`.
Capture SHA-256:
`e05aafccf97ee8d58b2559ed50d547b91888687ab19f833bda47654351fd766c`.

Kind remains on `6d71a30` until matching qualification. Production locality
bank/packet consumption is still absent: `kernelAdmitted`, `observedDelivery`
and `localityAdmission` remain false. L3/L4/L5/Q, Phase 9 and S1–S5 remain open.
No release pins or full platform status change.
