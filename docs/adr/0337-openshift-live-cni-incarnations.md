# ADR 0337: OpenShift Live CNI Incarnation Rollout and Transport Qualification

Date: 2026-09-13

Status: scoped cl02 live CNI/reply slice verified; matching Kind pending

cl02 now runs source `450de805d4b7471ee98597157ce9a5b8c514d4bd`:

- Controller: `quay.io/arencloud/unf-controller-dev@sha256:f4ef2cd493222f11d5c8056709bda35c3569ff399d55baaef0c9dc98f44c4198`.
- Agent/installer: `quay.io/arencloud/unf-agent-dev@sha256:95272eb329b5cadfd6cc58d94cf685a91591ae12434d800ea03243ebca2f6e49`.
- Installed CNI SHA-256 on all five Nodes: `e8917321db962ecc4eac238400c60ecc799cfcfaf67aaa98e20505f1ace43153`.
- Unchanged eBPF SHA-256: `d8551daad5f6222a8b9ddd7b3e7ed5d869bdea53c99b1e8c692f8ec0c205a27d`.

Anonymous registry inspection confirms immutable digests and OCI revisions;
isolated and live version responses match the committed runtime. The controller
and then each Node are advanced under the existing restart/termination guard.
The ConfigMap script replacement checks its resource version and prior exact
source. Every installed CNI hash and real zero-grace STATUS exchange is checked
before advancing. All Node UIDs are preserved, all current UNF containers have
zero restarts, and final controller/agent state is fully converged. No BPF pin,
encryption key authority, generation frontier or journal reset is performed.

## Attachment preservation and runtime evidence

Before rollout, 116 attachments are unbound schema-2 records. After rollout,
113 remain byte-for-byte equivalent records; three retire and are replaced by
new sandbox keys for new OAuth Pod UIDs. API events show the authentication
operator's ReplicaSet revision 19-to-20 rollout. Its workload spec is unchanged,
while the operator resource-version hash changes. The initiating cause of that
operator hash change is not attributed here. New records match the API Pod UIDs
and exact reused dual-stack addresses, with durable nonces. Old records are not
silently rebound or assigned nonces. Both worker journals are byte-identical
across rollout; normal new OAuth records require schema 4 on the control planes.

ADR 0336's expanded live gate independently creates three new test Pods, checks
their real runtime UID/nonce/address ownership, and requires normal retirement.
All three assertions and the complete scoped transport matrix pass: 24 allowed
requests, eight unsolicited reverse denials, IPv4/IPv6 TCP/UDP, cross-worker
PodIP, Service and translated ports. Underlay capture contains 181 WireGuard
frames, zero observed Required plaintext, 72 Native controls and zero reported
kernel loss. Capture is explicitly stopped and flushed after traffic.
The namespace is absent, the fleet is Native/converged, and all five CNI journals
are byte-identical to their post-rollout pre-fixture copies after cleanup.

Qualifier revision: `d0d9cf3412f8174d4641c2a0d084a1dfb3915de1`.
Result SHA-256: `7e3a4c1bbfc33a58077b56a76108754364c2f9d227c23a0f60141c4259d36346`.
Capture SHA-256: `b00d154300c7d6c86595ff2265cdedff1d66b34b8fab0d13898b53414fdc907f`.

## Logs and remaining boundaries

Controller, every agent and installer logs are retained before/during/after,
including per-Node old/new logs during rollout. The final review contains 589
lines / 153,937 bytes, below all per-file caps. It retains 262 existing-clsact
warnings, 184 bounded flow-history warnings, 51 proof-assistance warnings, 18
bounded topology-history warnings, 14 startup-barrier warnings, 12 rejected
plan requests, seven incomplete activation warnings (including two probe
rendezvous timeouts), three predecessor catch-up warnings, two known named-port
admission conflicts, one expired EgressPool watch and the known large-ipBlock
rejection. No observed ERROR/panic/OOM/verifier rejection or stopped-dataplane
match is found. These are operational findings, not a clean-log claim.

The retired controller's CRI directory is already absent when checked through
the host log tree; the parent and new controller directory are accessible.
Its pre-rollout log capture is retained, but its final termination interval
cannot be claimed complete. New-runtime traffic-validation logs are available.
No all-time or exhaustive restart-log coverage is asserted.

Commit/push this scoped result before matching Kind rollout and live gate.
Kind still runs `67c2772`. Existing unbound workloads remain ineligible for
new locality ownership; do not downgrade agents after nonce-bearing records
appear. L3's authenticated kernel consumer, L4/L5 Required locality/replicas,
Q full lifecycle and S1–S5 remain open. Release pins and full platform rows are
not promoted by this bounded slice.
