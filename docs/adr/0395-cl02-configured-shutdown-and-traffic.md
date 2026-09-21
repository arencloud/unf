# ADR 0395: cl02 Configured Shutdown, Recovery and Traffic

Date: 2026-09-21

Status: scoped cl02 recovery/traffic verified; matching live Kind pending

cl02 now runs immutable `6d71a30` images from ADR 0394. The guarded serial
rollout verifies all embedded revisions, unchanged CNI/BPF hashes, zero-grace
CNI protocol responses and unchanged Node UIDs. All eleven retiring regular
container log streams complete successfully. All 116 current CNI records are
byte-identical after rollout, configured recovery and final traffic cleanup.
Native baseline, key timing and authority/history state are not reset.

The first configured controller recovery attempt uses direct Pod deletion.
Although the controller logs a complete drain and exits zero, its ReplicaSet
creates seven never-started replacements rejected by kubelet's NodePorts
predicate while the old host-network Pod's ports are reserved. The next
replacement becomes Ready, but the qualifier waits on the failed Pods too.
That attempt is stopped and retained, not labelled successful recovery.

This is a qualifier workflow mistake: direct deletion bypasses the singleton
Deployment's existing Recreate sequencing. Existing full Phase 9 lifecycle
scripts correctly use `rollout restart`. The seven rejection records are
archived with exact UIDs, owner, timestamps and events, then only those Failed,
never-started test-created Pod objects are removed using UID preconditions.
No running workload, map, journal, key or history is cleared.

The corrected planned restart uses Recreate for the controller and an exact
UID-bound replacement of one configured worker agent. Complete Pod watches
prove both old processes finish with exit code zero and no restarts; each
logs shutdown request/completion. Replacements become Ready without crashes.
This qualifies a Native planned-recovery slice, not Required-mode recovery,
all-node disruption, power loss or a loaded drain deadline.

The complete expanded reply/inventory gate subsequently passes on runtime
`6d71a30984fa130f66c31bbfabdd170a3e63eb59`, qualifier
`ef0c03b01fc84ef3dddfa99c0c1c6c515f97f7e2`:

- 24 allows (twelve Required, twelve Native) and eight unsolicited denials.
- IPv4/IPv6 TCP/UDP across workers, PodIP, Service and translated Service ports.
- Three actual CNI UID/nonce bindings and retirements; two candidate replays,
  real inventory-count checks and Native retirements.
- 131 WireGuard frames, zero Required plaintext, 72 Native controls and zero
  kernel capture loss on `br-ex`.
- Namespace absent, all five Nodes Native, and fresh ordinary reports converged
  at policy 401 / Service 193. All current UNF containers are Ready, zero restarts.

Required admission takes 35 observations; Native cleanup takes eleven. Public
plan/recovery samples retain key rotation, exact-generation receipt mismatches,
duplex-proof retries and eventual Native settlement. The capture-container
lifetime 08:29:53–08:36:15 UTC includes waiting for the traffic-stage marker;
it is not the packet-capture interval. No low-latency recovery claim is made.
Locality `kernelAdmitted`, `observedDelivery` and `localityAdmission` remain false.

All current/retiring logs are reviewed. The final current-container window is
658,508 bytes with no ERROR or unknown-key-epoch recurrence. It contains
reconciliation/HTTP retry bursts during controller replacement, 263 clsact,
236 proof-assistance, 214 bounded flow-history, 158 plan-sync and 140 fact-replay
warnings, plus other retained retry/admission warnings. A point-in-time resource
sample is retained but is not an equal-workload performance or RSS comparison.

Evidence: `.artifacts/p9-sigterm-6d71a30-cl02-*` and
`.artifacts/p9-sigterm-cl02-*`, including the failed direct-deletion attempt.
Passing traffic result SHA-256:
`5c2eea691f11878682fed869abf47857b2b3fd33dbc29ab2761e4d272170954b`.
Capture SHA-256:
`d5201053ae8647c1f95124dba66748c1e607ad222d7c08fcfac75e76b0c113b7`.
Next: matching Kind live rollout, configured recovery and expanded gate. Full
locality consumption, L4/L5/Q and S1–S5 remain open; no release pins change.
