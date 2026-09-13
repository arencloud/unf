# ADR 0333: Candidate CNI Protocol Readiness Before Installation

Date: 2026-09-13

Status: verified locally; isolated cl02/Kind packaging qualification pending

The OpenShift installer formerly treated an existing Unix socket pathname as
agent readiness. A pathname can survive its listener, or still belong to an
older agent during replacement. Installing the schema-4 CNI executable at that
point would expose new runtime calls to an unavailable/incompatible server.

After ordinary ownership/drift checks, but before replacing any installed
binary, configuration or ownership marker, the installer now invokes the
candidate production CNI executable with STATUS. Only its successful current
transaction protocol response admits installation. This is not a VERSION query
to the client or a test for pathname existence. `statusGracePeriodSeconds: 0`
explicitly disables the ordinary outage lease fallback. Successful STATUS may
refresh the existing public readiness lease; failure cannot use it as evidence.
No attachment mutation or allocation occurs in this probe.

Each probe is externally bounded to five seconds. The nominal wait defaults to
180 seconds and accepts only canonical decimal values 1–180; a final in-flight
probe can extend the deadline by up to five seconds. An independent attempt
count also bounds retry work if the wall clock moves backward. Invalid,
overflowing and ambiguous wait strings are rejected. Lowering the wait changes
availability tolerance, never the required successful handshake. Failure
reports the final bounded CNI response and leaves owned artifacts unchanged.

Three integration tests execute the real CNI binary and real installer with
only fixed packaging paths remapped into a private temporary directory. Unix
fixture peers verify STATUS requests use the current transaction schema. Cases
cover old v2/v3 responses, malformed responses, valid initial installation,
valid upgrade, retained old binary/marker on failed upgrade, a stale socket
beside a fresh owner-only lease, and invalid wait settings. These peers are
test doubles, not proof of a live agent rollout or hostile root protection.
The older shell installer fixture now responds with a versioned STATUS result
instead of opening a socket and immediately discarding the request.

All 787 workspace tests pass (26 environment-specific tests remain ignored),
as do strict workspace/all-target/all-feature Clippy, formatting, shell syntax
and OpenShift runtime rendering. The isolated verification target remains on
`/tmp` because of the earlier workstation Btrfs metadata-reservation issue.
No filesystem repair is performed. A dedicated immutable packaging-test image
builds the production executable and the same compiled integration tests.

Next: qualify this bounded packaging slice on cl02, then the identical image
on retained Kind, with logs and artifact provenance. The existing Kind init
installer topology is not silently converted by this change; its live upgrade
ordering still needs explicit qualification before new-runtime rollout.
Live CNI/agent images remain unchanged. This does not close L3 locality
consumption, L4/L5/Q, either full Phase 9 platform row or stabilization S1–S5.
