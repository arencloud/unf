# ADR 0390: cl02 Tombstone Repair and Inventory Qualification

Date: 2026-09-21

Status: scoped cl02 gate verified; matching Kind and full Phase 9 closure pending

Runtime and qualifier are `8db97bb8029ef21cd053e903cbd4c751d753fd48` (ADR 0389).
Immutable images were independently version/ABI checked and anonymously pulled:

- Controller: `quay.io/arencloud/unf-controller-dev@sha256:e77b265dc23bec4cb4f0c437d36110bab9c470b7b46d63505b56276869e37966`.
- Agent/installer: `quay.io/arencloud/unf-agent-dev@sha256:206f845192b8492a7791b25c4052468fcb73a59eb4e0a4bc85ec40da24f8844f`.
- CNI SHA-256 remains `812b0e33a46ea705c64af35fe6cf96598bb2dd0bfdad6537bd5934509ff024b3`.
- BPF SHA-256 remains `d8551daad5f6222a8b9ddd7b3e7ed5d869bdea53c99b1e8c692f8ec0c205a27d`; map ABI 15 / encryption ABI 2.

The serial rollout preserves all five Node UIDs, the Native cluster baseline,
key timing and all 116 CNI records byte-for-byte. Its first attempt stops at the
second Node: the installed binary is present but the CNI socket returns code 50,
connection refused during startup. This failure is retained. Independent checks
then prove both new agents Ready with zero restarts and successful zero-grace
STATUS. The guarded resume advances only the remaining three exact old-image
Pods, retaining each STATUS attempt and retrying only code 50 within a bounded
window. They pass on attempts four, three and three. No safety check, status
grace, key frontier or journal is reset. All eleven retiring log streams end
successfully across the two attempts; the intentionally interrupted followers
from the first attempt remain recorded separately.

The complete expanded cl02 gate passes:

- 24 allows: twelve Required requests and twelve Native controls.
- Eight unsolicited reverse-flow denials.
- IPv4/IPv6, TCP/UDP, cross-worker PodIP, Service and translated Service ports.
- Three exact live CNI Pod-UID/creation-nonce bindings and three retirements.
- Two replayed locality candidates, actual journal inventory counts, and two
  Native candidate/inventory retirements.
- 312 captured WireGuard frames, zero Required plaintext frames, 72 Native
  plaintext controls and zero kernel capture drops.
- Fixture Namespace absent; all five generations return to Native and ordinary
  reports finish fresh/converged at policy 413 / Service 193.

The capture container runs 07:28:52–07:32:20 UTC; that lifetime includes its wait
for the traffic-stage start marker and is not the actual packet-capture duration.
The gate reaches Required admission on observation 17 and Native cleanup on 19.
All 116 CNI records are again byte-identical after cleanup. This is bounded
candidate/inventory qualification, not local Required packet admission:
`kernelAdmitted`, `observedDelivery` and CNI `localityAdmission` remain false.

Before, during and after logs, all retiring streams and 23 bounded public-only
plan/recovery samples are reviewed. Final current logs total 203,216 bytes and
contain no ERROR, missing-key-epoch or per-packet INFO entries. They do contain
259 clsact, 243 flow-history, 57 proof-assistance, 37 plan-sync, fourteen
activation, thirteen topology-history and twelve startup-fence warnings, plus
Service-sync and existing ipBlock/named-port admission findings. The union of
retiring streams has 6,468 distinct WARN entries, dominated by controller-
replacement retries. No clean-log or interruption-free claim is made.

Targeted lifecycle logs now expose successful activation, retirement and plan
epochs without key bytes. The old unknown-epoch failure does not recur in this
run, but this does not prove a sole historical cause or erase retained failures.
An optional SSH handshake inspection cannot run because RHCOS has no `wg`
executable; no handshake observation is claimed from it. The independent
qualified underlay capture supplies the gate's ciphertext evidence.

Both isolated image-version processes require SIGKILL after the ten-second
SIGTERM grace. Source inspection finds their main shutdown waits use `ctrl_c`,
not a SIGTERM listener. This remains a stabilization/recovery finding; graceful
container termination is not qualified by this gate.

Evidence is under `.artifacts/p9-retired-8db97bb-cl02-*` and
`.artifacts/p9-retired-cl02-*`. Passing result SHA-256:
`9567242f484411f38c33ed83493d601d17a0a18b06e9a40193d4a4722c7eadaa`.
Capture SHA-256:
`7d6e9d4f05da69ced452287e8d5ff159d2039f780a5b30d51d06bb08aadd3896`.
Next: identical-image persistent Kind rollout and complete scoped gate. Full
authenticated locality consumption, L4/L5/Q and S1–S5 remain open. No release
pins change and no credentials enter Git.
