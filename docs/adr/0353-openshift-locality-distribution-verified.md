# ADR 0353: cl02 Locality Distribution and Required Reply Qualification

Date: 2026-09-14

Status: verified on cl02 for placement-candidate distribution and existing
cross-worker Required replies; matching Kind pending

The fresh complete run uses ADR 0352's immutable `f984db9` controller and
agent/installer images, with qualifier
`f767a7ca34709fbb12b058c0ac0a868e08754ec7`. The previous cleanup-observer failure
and retired-controller log gap remain recorded; neither is retrospectively
converted into a pass.

The full gate passes:

- Three real runtime CNI workload-UID bindings, three creation nonces and three
  normal fixture UID retirements.
- Authenticated placement replay on both workers, joined to their public plans
  and fresh identity/routing coordinates; both candidates retire under Native.
- 24 allowed requests (12 Required and 12 Native controls), and eight denied
  unsolicited reverse requests across IPv4/IPv6 TCP/UDP, cross-worker PodIP,
  Service and translated Service ports.
- 188 WireGuard frames, zero captured Required plaintext, 72 Native plaintext
  frames and zero kernel capture loss. The observer is explicitly stopped after
  all probes and exits zero. Packet timestamps span 22:52:51.350185 through
  22:53:21.853656 UTC on September 13. The container's longer
  22:48:18–22:53:29 lifetime includes waiting for the capture-start marker;
  it is not the actual packet-capture interval.
- Namespace and EncryptionPolicy absence and fresh full Native convergence on
  all five agents, at policy revision 445 and Service revision 203.

Evidence is retained locally under
`.artifacts/p9-required-reply-f984db9-cl02-locality-rerun`.
Result SHA-256:
`5a56ff49fb1795447fda39f26fc17eb99c8ce309305372de0a24e78949c90d9e`.
Capture SHA-256:
`79c66278a850b5a65152ad4e1934bd79b0fe038516e2469c0c3d43854eaa3fad`.

Post-run journal comparison preserves 115 existing records unchanged. The
remaining worker record is replaced, not retroactively rebound: an old unbound
sandbox is retired, and a new UID/nonce-bound sandbox owns the same dual-stack
lease. API inventory identifies its UID as the OpenShift Insights periodic
gathering Job Pod created at 22:46:01 UTC. That worker migrates schema 2 to 4;
its other nine records remain identical. The other four journal files remain
byte-identical. No journal, map, frontier or cluster reset is performed.

The final complete 20-minute UNF log window contains 683 lines / 180,876 bytes
and includes the full rerun. Controller, all five agents and all installers
are reviewed; current containers have zero restarts and no previous-container
logs are therefore required. No ERROR, panic, OOM or verifier rejection is
observed. Bounded-history warnings, proof/plan/activation retries, clsact
EEXIST, key catch-up and an earlier Service-sync warning remain visible.
The API TLS/OpenAPI timeout investigation, controller-startup retry burst and
existing operator/policy-limit findings remain stabilization work, not erased
by this successful feature run.

Both `kernelAdmitted` and `observedDelivery` remain false. This verifies
distribution and candidate retirement, not a same-Node Required plaintext
permission, continuous attachment lifetime, banked packet consumer, full Phase 9
or S1–S5. Retained Kind must next run the identical immutable runtime images
and expanded gate before consuming-locality work advances.
