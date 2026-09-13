# ADR 0354: Retained Kind Locality Distribution Qualification

Date: 2026-09-14

Status: verified for candidate distribution and existing cross-worker replies

After ADR 0353's complete cl02 pass, retained Kind is upgraded to the identical
`f984db9` runtime and immutable controller/agent digests recorded in ADR 0352.
The isolated container store and all three Node UIDs are preserved. The first
preflight stops before Pod mutation because containerd's import retains only
the tag, not the required digest-named reference. The corrected runner checks
the imported manifest and creates the missing exact reference without replacing
an existing one, then verifies its digest on every Node.

Controller-first and serial agent rollout passes. All three init installers
complete with exit zero and no restart; actual installed CNI SHA-256 is
`09129e9c91cc3434b0253bf7d4c811870f2e6e72ce6bf3e4b88eba7b03a4cd47`, and all three
zero-grace live-socket STATUS checks succeed. Original RollingUpdate strategy
is restored after fleet admission. The four independent retiring regular-
container log followers exit zero; all three completed init logs are retained.
Existing worker journal bytes and the explicitly absent host-network-only
control-plane journal remain unchanged. Public generation coordinates advance
from 1789335531774/1789335568801 to 1789340980449/1789340987906, without resetting
the durable predecessor or frontier.

Qualifier `1503994b5d73908c04cc381ddda61fbcae7e6d6e` passes the full expanded gate:

- Three real CNI UID bindings, three creation nonces and three normal fixture
  UID retirements.
- Two exact worker placement replays and two Native candidate retirements.
- 24 allowed requests and eight unsolicited reverse denials across dual-stack
  TCP/UDP cross-worker PodIP, Service and translated Service ports.
- 73 WireGuard frames, zero captured Required plaintext, 90 Native plaintext
  frames and zero kernel capture loss; explicit post-probe stop and exit zero.
- Namespace absence, unchanged original CNI journals and all three agents fresh
  and converged under Native, policy revision 43 and Service revision 19.

Result SHA-256:
`58cee88ffbc0231529aa1b171abc23f332e584441263ec65bec666b36188f632`.
Capture SHA-256:
`3fd7ea3c8218b34868f6792ea605bbd7027e9ef52dbe89c9a8110594258b1492`.
Local evidence: `.artifacts/p9-required-reply-f984db9-kind-locality` and the
associated `p9-locality-kind-*` rollout/state/log/CRI captures.

Controller, agents and installers are reviewed before, during and after; all
new containers have zero restarts. Final retained current/rotated agent CRI
logs contain 64,671 lines / 38,294,661 decoded bytes, including the complete
new-container validation window. They show startup fleet fences, queued
activation and proof retries, but no ERROR, panic, OOM or verifier rejection.
Retiring logs also retain controller-replacement request failures. Per-packet
INFO amplification remains a measured log-volume finding for S3, not evidence
of low CPU/memory use or uninterrupted transitions.

This closes matching-platform qualification of authenticated placement
distribution, candidate status/retirement and the stricter live CNI readback.
`kernelAdmitted` and `observedDelivery` remain false. Continuous source/peer
lifetime, banked policy-first locality consumption, local/remote replica
qualification, full Phase 9 lifecycle and S1–S5 remain open. Release pins are
not promoted from this scoped result.
