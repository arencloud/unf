# ADR 0276: Deadline-bound responders after local probe timeout

Date: 2026-09-12

Status: Implemented; successor cl02 qualification pending

## Context

ADR 0275's candidate passed initial Required migration, but the post-fixture
generation stalled with active and pending endpoint rendezvous timeouts and
deferred epoch catch-up. The socket engine kept a responder after success, yet
closed it after a local four-second timeout even when the authenticated round
was still live. An isolated delayed-peer regression failed on that behavior:
the later endpoint could not obtain a response despite using the exact round.
This is one demonstrated scheduling gap, not attribution of every cl02 failure.

## Decision

On local exchange timeout, hand the existing socket and indexed work to the
same exact-frame responder used after successful completion. Return an error,
never a partial transcript or activation capability. Do not extend the original
round deadline, change the four-second attempt cap, relax address/family/nonce
checks, or alter kernel counter verification. Expiry wins over ready receives
in the responder's event selection.

Drain all bounded family exchange tasks before propagating the first error;
otherwise dropping their task set cancels the other family's responder handoff.
No full contracts are retained by leases, and the timeout path transfers its
existing work instead of cloning it. There is no wire, checkpoint or BPF schema
change and no new dependency.

## Verification boundary

The privileged isolated regression first requires the early endpoint to time
out without a transcript. It rejects a foreign round and a changed nonce, then
allows the late endpoint's exact request while the round is live, and requires
silence after expiry. It is included in the isolated path-executor workflow;
that workflow separately proves marked dual-stack WireGuard delivery, duplex
counters, peer-loss denial, fresh recovery and ciphertext-only underlay capture.
The loopback regression alone does not prove encrypted delivery or remote quorum.

Full workspace tests, strict lint and the 4,096-round-per-family kernel fixture
must pass before publication. cl02 runs before successor Kind. Checkpoint size,
rotation under workload changes and measured heavy-load capacity remain open.
