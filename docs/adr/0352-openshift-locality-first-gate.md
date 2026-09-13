# ADR 0352: cl02 Locality Candidate Rollout and Failed Cleanup Observer

Date: 2026-09-14

Status: runtime rolled out; first complete qualification attempt failed

After ADR 0351's observer repairs, cl02 completes the guarded agent rollout on
source `f984db9e8b041c014814958054a1908e9829233c`. Controller image:
`quay.io/arencloud/unf-controller-dev@sha256:27ca5f02cc76a6c3f5694d5e730f1b0b2399f7954b5c41f277c94061a59e6c5e`.
Agent/installer image:
`quay.io/arencloud/unf-agent-dev@sha256:4062add8cd5ead92cdd7decc293de44851eaab1d012fc075802d41ffe8065eb7`.
Anonymous registry reads and isolated version endpoints confirm provenance.

Installed CNI SHA-256 on all five Nodes:
`09129e9c91cc3434b0253bf7d4c811870f2e6e72ce6bf3e4b88eba7b03a4cd47`.
Each passes actual zero-grace STATUS on the live transaction socket. BPF remains
`d8551daad5f6222a8b9ddd7b3e7ed5d869bdea53c99b1e8c692f8ec0c205a27d`, core ABI 15 /
encryption ABI 2. Node UIDs remain unchanged. All 116 CNI attachment records are
byte-identical before/after rollout; public admitted generations do not regress.
All new containers are Ready with zero restarts. All ten retiring agent/installer
log streams finish with exit 0. The earlier controller termination gap remains
explicitly unavailable; it is not repaired by these later observations.

The first expanded gate on qualifier `41e9563` establishes:

- Three real runtime CNI UID/nonce bindings.
- Exact Required placement replay on the two workers, with 24 and 32 local
  address records, joined to public plans and fresh reported coordinates.
- 24 allowed requests and eight unsolicited reverse denials across IPv4/IPv6
  TCP/UDP, cross-worker PodIP, Service and translated Service ports.
- An explicitly stopped capture, 22:37:30–22:41:12 UTC on September 13:
  175 WireGuard frames, zero captured Required plaintext, 72 Native plaintext
  frames, and zero kernel capture loss. Capture SHA-256:
  `861005dae972c97f17f2cba9907c81d8a3258b100e351a1ce0b61ce61534dd80`.

The overall gate **fails** during Native cleanup readback: a kubectl request
reports a TLS handshake timeout and the downstream gzip decoder receives an
incomplete stream. The failed attempt is retained, not changed into a pass.
The fixture was already deleted. Independent subsequent reads confirm Namespace
and EncryptionPolicy absence, cleared placement candidates, fresh full agent
convergence and exact original CNI journal bytes. No state reset is used.

Health investigation finds all Nodes/API-server containers Ready, with no new
API-server restarts; existing guard-container restarts predate this run. The
readyz checks pass and twenty fresh API connections succeed in 248–286 ms each.
The three API-server log windows contain 2,207 lines / 382,144 bytes, including
aggregated OpenAPI and handler timeout errors. They do not establish the exact
cause of the failed observer handshake. Insights upload and unsafe network-
operator configuration findings persist. Resource snapshots after failure are
not evidence of resource usage at failure or a sustained-load envelope.

UNF logs across before/rollout/during/after preserve startup barrier and clsact
EEXIST warnings, proof/plan/activation retries, bounded history warnings, and the
known large-ipBlock/named-port admission limits. Retiring agent streams also
show a substantial HTTP 503 retry burst during controller initialization.
No observed UNF ERROR/panic/OOM or verifier rejection is found in those captured
windows; this is not a clean-log or interruption-free rollout claim.

A fresh complete cl02 run is required before Kind advances. Neither L3 packet
consumption nor full Phase 9/S1–S5 is verified by the successful portions above.
