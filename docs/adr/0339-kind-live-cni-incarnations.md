# ADR 0339: Retained Kind Live CNI Incarnation Qualification

Date: 2026-09-13

Status: scoped matching Kind live CNI/reply slice verified

After committing and pushing cl02's ADR 0337 result, retained Kind is advanced
to the identical immutable controller and agent/installer images documented
there, source `450de805d4b7471ee98597157ce9a5b8c514d4bd`. The eBPF object and
ABIs are unchanged. All three installed CNI binaries have SHA-256
`e8917321db962ecc4eac238400c60ecc799cfcfaf67aaa98e20505f1ace43153`.
Live controller/agent version responses match that source.

Kind retains its init-installer topology. Each init must complete successfully
without restart; the installed hash and a real zero-grace CNI STATUS exchange
are checked before advancing. ADR 0338's staging fence rejects failed or
restarted init containers. The original RollingUpdate strategy is restored,
all Node UIDs are unchanged, and all current UNF containers are Ready with zero
restarts. There is no cluster recreation or journal/map/frontier reset.

## Live result

The expanded gate, qualifier `5646d5fa25f78ed098837cb2df82b556c5251037`, verifies
three actual containerd Pod UIDs, distinct nonzero durable creation nonces and
exact dual-stack leases, followed by normal retirement of all three UIDs.
It passes 24 allowed requests and eight unsolicited reverse denials across
IPv4/IPv6 TCP/UDP, cross-worker PodIP, Service and translated Service ports.
The explicitly stopped/flushed `eth0` capture observes 242 WireGuard frames,
zero Required plaintext, 90 Native controls and zero reported kernel loss.

Result SHA-256: `5e55ffd1062b1b764c5131049871d7afbe698f11b94a1967bf70a5d0253752fa`.
Capture SHA-256: `d7cd00635d155de505819b19c37eeda4c49a2099ffd324bba011f72eaa416a99`.

The fixture namespace is absent and the fleet is Native/converged at policy
revision 41 and Service revision 19. Both worker journals are unchanged across
rollout and return to their exact pre-fixture content after cleanup: one legacy
unbound record on worker, zero on worker2, both schema 2. The control-plane
journal is absent before and after, with all its current Pods host-networked;
the observer records this explicitly rather than manufacturing an empty journal.
New nonce records temporarily require schema 4 and are retired, not rebound or
stripped of ownership. No downgrade is performed.

## Log review and open boundaries

Controller, all agents and init installers are reviewed before/during/after,
with old/new agent logs during rollout. The final API review is 38,644 lines /
21,271,241 bytes, each file below its 16-MiB cap. Retained current and rotated
agent CRI files add 81,045 lines / 47,981,729 bytes of overlapping coverage.
They contain 17 proof-assistance warnings, 14 rejected plan synchronizations,
six incomplete exact-receipt activation warnings and three startup-barrier
warnings. Observed 503 responses remain reliability findings, not clean logs.
No ERROR/panic/OOM/verifier rejection or stopped-dataplane match is observed.
Kind's per-packet INFO amplification remains S3 work; no resource saving is
claimed. Init logs are empty with independently checked Completed/exit-0 status.

The old controller follower times out. Its exact retired host CRI directory is
already absent when checked through the accessible Node log tree, so the final
termination interval remains a documented coverage gap. New-runtime traffic
logs are retained; no exhaustive all-time log claim is made.

This closes the matching live runtime-incarnation prerequisite, not Required
locality admission. Both fleets now run `450de80`. Authenticated kernel
consumption, same-Node/mixed-replica gates L4/L5, full lifecycle Q and S1–S5
remain open. Full Phase 9 platform rows and release pins are not promoted.
