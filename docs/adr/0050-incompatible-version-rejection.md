# ADR 0050: Incompatible version rejection before dataplane mutation

Status: Accepted and live verified on dual-stack Kind

## Context

ADR 0047 and ADR 0049 qualify mixed controller/agent operation only when every
published persistent-state and wire-schema field is identical. An incompatible
tuple therefore needs a fail-closed boundary that is earlier than persistent
BPF map adoption, policy staging, or active-bank selection. The boundary must
remain useful when the controller is unavailable, because last-known-good
offline agent recovery is an existing availability contract.

## Decision

Before any persistent BPF filesystem or map access, a connected agent now:

1. requires the configured pin directory basename to equal its compiled
   persistent ABI (`v3` for ABI 3); and
2. when the controller is reachable, reads compatibility schema v1 over the
   existing CA-pinned internal TLS channel and requires an exact persistent-ABI
   and wire-schema tuple.

The internal controller API exposes `GET /v1/version` for this preflight. A
transport-unavailable controller does not prevent last-known-good offline
startup, but the local ABI-directory invariant still applies independently. A
reachable malformed, unknown, non-controller, or unequal compatibility response
stops the agent before `load_persistent_ebpf` can create, open, or adopt pins.

Running agents continue to validate a policy snapshot's schema before changing
desired epoch/revision, compiling entries, touching the inactive bank, or
committing the active bank. Schema rejection increments the existing policy
sync-error counter and retains the last-known-good policy maps.

`make kind-incompatible-version-test` accepts only a clean committed worktree.
It archives that exact revision and creates local test-only controller and agent
images with policy snapshot schema 4 changed to 5 and persistent ABI 3 changed
to 4. The images carry labels describing both deliberate mutations and are not
release artifacts.

The two-node gate first replaces one current agent with the incompatible image.
It requires the local ABI/path error and an identical canonical digest across
all eleven persistent maps before and after rejection. After current-agent
recovery, it deploys the incompatible controller, observes two policy-schema
rejections per agent, and proves that desired/applied policy state, entry count,
active bank, and the six pinned policy-map digests remain identical within that
incompatible window. TCP/8080 must remain allowed and TCP/9090 denied
continuously, and the current tuple must reconverge at the end.

## Evidence

On 2026-08-27, the complete target passed from clean implementation revision
`6d7dd2808cfa6d2295b0f58c98f8d182ed9c24c4`. The current images reported policy
schema 4 and persistent ABI 3; the derived fixtures reported schema 5 and ABI 4.
The incompatible agent stopped before BPF access, both current agents repeatedly
rejected schema-5 snapshots without policy-state or pinned-map mutation, the
continuous enforcement probe reported no outage or breach, and current/current
recovery converged.

Formatting, strict workspace lint, 167 workspace tests, the release eBPF build,
manifest rendering, complete shell syntax, clean-worktree refusal, and Make
target expansion also passed.

Verifier development retained the causes of its preliminary retries. The first
comparison incorrectly required a compatible recovering agent never to restage
an equivalent bank. The second captured map state before the inspection
DaemonSet's own watched Pods had converged. The third compared across legitimate
old-controller observation of Deployment rollout topology. The final gate
therefore places a convergence barrier after helper creation and measures two
rejections wholly inside the incompatible-controller window. None of these
retries showed incompatible code mutating BPF state.

## Consequences

UNF now has repeatable negative evidence for one deliberately incompatible
policy-schema/persistent-ABI boundary. This verifies rejection and recovery; it
does not define a schema translator, dual-read/write window, persistent-state
migration, or clean rebuild. Those behaviors remain milestone 2.3. Unsupported
downgrade classification and operator-facing rollback reporting also remain
separate tracked work.

ADR 0051 subsequently verified the deliberate snapshot-driven clean-rebuild
choice for milestone 2.3; this ADR's negative rejection boundary remains
unchanged.
