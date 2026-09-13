# ADR 0301: Native Fixture Adoption Fence

Date: 2026-09-13

Status: qualifier implemented and locally checked; live cl02-first run pending

The Native gate previously began allowed probes after Pod readiness and local
listener health, without first proving that the fixture was visible in the
controller and adopted by agents. Its final convergence check could not prove
that an earlier positive packet traversed the intended policy/identity cut.
ADR 0299's few initial successful Pod probes are therefore not a substitute
for a completed gate or evidence of policy adoption at those instants.

Add a bounded pre-traffic adoption fence:

- Controller topology must contain all three exact Pod placements and assigned
  IPv4/IPv6 addresses with nonzero identities, plus both Service ClusterIP sets
  and ready backends.
- All 32 combinations of server, ingress/egress direction, IP family, protocol
  and forward/reverse initiation must have the expected policy explanation:
  forward Allow, unsolicited reverse Deny, with nonzero policy provenance.
- Explanations must agree on one policy revision. Every expected agent must be
  fresh, Ready, BPF-loaded and converged on that revision in the observed
  controller epoch, with the observed identity cut applied.

Each attempt retains its public topology, explanations and agent report under
ignored diagnostics. Observation failure, missing identity, stale epoch,
unobserved Service or inconsistent revisions cannot pass. The 180-second
adoption window is checked between bounded requests; no admission, policy or
encryption barrier is bypassed. Actual 24 allowed and eight denied packet
checks, local listeners and final positive cleanup remain mandatory. Adoption
is not encryption activation, packet proof or uninterrupted-service evidence.

The jq contract tests reject unknown/zero/malformed identities and policy IDs,
wrong verdict/direction/family, stale epochs/revisions, missing agents,
nonboolean readiness, wrong Pod placement/address, and absent Service backends.
The existing TCP/UDP observation-safety tests and shell syntax checks pass.
This qualifier does not alter runtime `64ad559`; its new live results must name
the independent qualifier revision. Run cl02 before retained or fresh Kind.
