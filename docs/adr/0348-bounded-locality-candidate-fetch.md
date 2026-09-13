# ADR 0348: Bounded Background Locality Candidate Fetch

Date: 2026-09-14

Status: agent source slice verified locally; live qualification pending

The agent acquires ADR 0347 placement candidates only when its admitted plan
contains Required demand and its desired/applied identity and remote-route
coordinates agree with that plan's controller epoch. Bootstrap Node incarnation
and recipient must agree. Native/no-demand operation performs no locality fetch.
An unchanged plan digest and placement context reuse the ephemeral candidate;
there is no new per-packet request or periodic full download of unchanged data.

HTTPS uses the existing reloading pinned-CA controller client and current agent
token. The shared internal controller client now refuses redirects. The locality
path additionally verifies the response URL and requires HTTP 200. Both declared
size and actual chunked bytes are bounded at 16 MiB; unknown Content-Length does
not bypass the cap. Geometric buffer growth is requested within that bound.
Truncation, unexpected status, failed replay and changed applied coordinates
cannot install a replacement candidate. Credentials are never added to evidence.

Fetch/replay runs outside the dataplane event-loop wait path, in one background
work slot. CPU replay uses the blocking worker pool. Cancelling a running replay
does not release the slot until that replay really exits, preventing repeated
cut changes from queuing detached CPU work. The event loop consumes only a
finished result and rechecks the actual applied coordinates before handoff.
Pending requests are aborted when discarded. Request nonces are not persisted
or reused. The cache starts empty after restart and grants no kernel permission.

Verification: 803 workspace tests pass, 26 remain explicitly ignored. Six new
agent tests cover Required-only/current-cut acquisition, all epoch/revision
coordinates, exact byte budget, real loopback chunked/oversized/truncated HTTP,
unexpected status, cache identity/clear behavior and cancellation while a
blocking replay still owns its single slot. The loopback transport tests are
not TLS/authentication qualification. Formatting and strict Clippy are required
before commit. Existing wire and durable generation goldens are unchanged.

The current cl02 runtime is unchanged (`450de80`). A refreshed 20-minute review
of the controller, all agents and installers contains 419 lines / 96,374 bytes:
418 bounded flow-history warnings and one rejected reciprocal key-attestation
row. No observed ERROR/panic/OOM, verifier rejection or stopped-dataplane match
is found. All current containers are Ready with zero restarts. All five agents
are fresh/converged at policy revision 399 / Service revision 204. These are
baseline observations, not qualification of the new runtime or clean-log claims.

Next: observable placement-candidate status, authenticated live distribution
qualification on cl02 then matching Kind, and actual banked packet consumption.
Placement replay, source/peer lifetime, policy permission, generation admission
and observed delivery remain distinct. Full L3/L4/L5/Q and S1–S5 remain open.
Bounded work and unchanged-cut reuse are implementation properties, not measured
sustained-load CPU/memory savings or an unlimited-scale claim.
