# ADR 0217: Agent Cursor High-Watermark Recovery

- Status: Accepted and implemented for Phase 9.9
- Date: 2026-09-11

## Context

The exact Phase 9 Kind rerun reached a narrow controller-replacement window.
One Node had durably admitted a naturally rotated successor, but the periodic
controller checkpoint still contained the fleet predecessor. After replacement,
the restored catalog correctly refused regression; however, it repeatedly tried
to return that predecessor to the ahead Node. The response was not a valid
successor, the other Nodes had no reason to advance, and duplex activation could
not converge.

Persisting each pull synchronously would put Kubernetes API latency in the plan
delivery path and still could not make the agent admission and controller
checkpoint one atomic transaction. Discarding the ahead agent state would break
persist-before-compile rollback protection.

## Decision

An authenticated, current Pod-bound Node plan cursor is a recovery high-watermark
when its generation is strictly ahead of the restored complete fleet catalog.
The controller then publishes one complete fleet cut strictly beyond that
cursor. Every member pulls the same cut and rejoins the normal proof-carrying
activation protocol. A cursor equal to or behind the catalog remains only an
acknowledgement and cannot create generation churn.

The high-watermark does not grant dataplane authority, claim activation, weaken
duplex proof, or reuse the orphaned plan. Normal Node UID, controller-incarnation,
membership, monotonic transition, nonce, and capsule checks remain mandatory.

## Consequences

- An admitted successor cannot be stranded by a controller checkpoint race.
- Recovery converges forward as a fleet; the controller never rolls an agent
  back or treats missing Required authority as Native.
- Normal polling remains coalesced because only a strictly ahead durable cursor
  bypasses the restored-cut hold.
- The qualification waits inspect convergence directly once per second, so one
  bounded 240-second stage cannot accidentally nest another 240-second wait.

## Verification

The controller regression test reconstructs an older catalog behind an actual
successor cursor and requires a new complete cut beyond it. The static Kind gate
checks the bounded direct convergence loop. The full three-Node dual-stack Kind
transaction, including natural rotation followed immediately by controller
replacement, remains mandatory before image publication or cl02 deployment.
