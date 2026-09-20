# ADR 0387: cl02 Inventory Rollout and Required Admission Failure

Date: 2026-09-21

Status: rollout verified; expanded Required qualification failed

cl02 now runs ADR 0386's immutable `d007071` controller and agent/installer
images. The guarded serial rollout verifies every embedded runtime revision,
the installed CNI hash and the live zero-grace transaction STATUS on all five
Nodes. Node UIDs are unchanged. All 116 CNI records remain byte-identical
across rollout, and all eleven retiring controller/agent/installer log streams
finish with exit zero. New UNF containers are Ready with zero restarts.
No BPF object, map ABI, key lifetime, encryption baseline or journal is reset.

The expanded gate on qualifier `cc78db5` **fails** at
`selective-required-admission` after its bounded 360-second wait. It creates
the three UID/nonce-bound fixture Pods and adopts all 32 policy outcomes at
revision 406, but does not reach its traffic/ciphertext or inventory-retirement
acceptance stages. A separately captured live source candidate reports three
attachments, six addresses and 1,260 logical payload bytes; both admission and
delivery claims remain false. This observation does not convert the failed
complete gate into a pass.

Logs identify 173 plan-compilation failures against **unknown key epoch 6117**,
plus 315 deferred key catch-ups waiting for a draining predecessor. The existing
accelerated configuration is unchanged: key lifetime 600 seconds, rotation
480 seconds before expiry, jitter five seconds and drain 30 seconds. The exact
causal chain between key publication/retirement, pending generation ownership
and the controller's retained plan requires a regression-backed investigation.
The pending-work guard on transport-free retirement is a lead, not a proven
sole cause or permission to remove safety checks.

Failure evidence: `.artifacts/p9-inventory-d007071-cl02-gate/failure.json`,
SHA-256 `233ff35b57d1c1538e9cd9013b5f968599912033150187a51568cb4aeb03c2f5`.
Rollout evidence: `.artifacts/p9-inventory-d007071-cl02-rollout`.
Before/during/after logs and retiring streams are reviewed. The final captured
current-container window totals 317,102 bytes with no ERROR entries, but contains
the above failures at WARN level, startup fences, clsact EEXIST, proof/activation
retries, bounded-history warnings and known ipBlock/named-port admission limits.
Retiring streams contain 7,779 warnings, including a substantial controller-
replacement HTTP retry burst. No clean-log or interruption-free claim is made.

Failure cleanup removes the fixture Namespace and EncryptionPolicy. All five
CNI journals are again byte-identical to the pre-rollout inventory, so the
fixture attachments have retired without deleting existing records. Public
policy/Service reports are fresh/converged at 413 / 193 under the restarted
controller epoch; this is not encryption-generation convergence. A subsequent
public recovery read shows four Nodes still pending at active generation
1789944122580 and one at 1789944620247. All report empty active, pending and
retiring transport-plan lists. Do not call this a completed Native lifecycle
gate merely because Pods and ordinary policy/Service reports are Ready.

Next: reproduce the missing-epoch/pending-generation boundary locally, preserve
all authority and history, implement only a proof-backed repair, and rerun the
complete cl02 gate before Kind. The retained Kind runtime is unavailable after
the workstation reboot; a separate fresh persistent cluster needs an explicit
decision and cannot replace retained-state continuity evidence. L3, L4/L5/Q,
Phase 9.8/9.9 and S1–S5 remain open. No release pins are updated.
