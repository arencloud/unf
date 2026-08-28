# ADR 0061: Portable veth state is deterministic and exactly owned

Status: Accepted and implemented for the standalone full-CNI link primitive

## Context

The schema-v2 attachment transaction from ADR 0060 durably fixes the namespace,
host interface name, container interface name, MTU, and dual-stack lease before
host mutation begins. The next operation must survive interruption without
guessing whether a same-named kernel link belongs to UNF. It must also enter the
container network namespace without changing a reusable runtime thread and must
never shell out from the production lifecycle.

Returning CNI ADD success after links but before routes would expose an
unreachable Pod. Link qualification therefore remains a standalone primitive;
production ADD/CHECK/DEL wiring waits for the native route operation in milestone
6.5 so link and route application can share one rollback boundary.

## Decision

The new `unf-link` crate derives a `VethPlan` directly from one durable
`AttachmentRecord`. Linux interface names remain bounded to 15 bytes. The
temporary peer name is deterministic, and the plan derives two stable locally
administered unicast hardware addresses from the durable host name. Those
addresses are applied atomically at pair creation and are the interruption-safe
creation identity. Exact role-specific aliases are then applied to both ends.

Production mutation uses `rtnetlink`, not `ip`. Apply creates or resumes the
owned pair, brings the host end up, moves the peer through an already opened
namespace file descriptor, renames it to the requested container name, applies
the validated MTU and both leased addresses, and reads all state back from the
kernel. Namespace entry uses safe `rustix` `setns` on a newly created disposable
OS thread with its own current-thread Tokio runtime. The caller and reusable
runtime workers never change namespaces. The namespace descriptor is opened
with `O_NOFOLLOW` and `O_CLOEXEC`.

Replay accepts only a veth with the deterministic name, MTU, and hardware
address plus either the exact alias or an absent alias from an interrupted
configuration. It restores aliases, administrative state, and missing managed
addresses, then performs strict readback. An unexpected alias, type, hardware
address, MTU, or endpoint shape is a conflict.

Delete validates exact type, MTU, and hardware address plus either the role alias
or its interruption-safe absence before removing the host endpoint. Kernel veth
semantics remove its peer atomically. If the host endpoint is absent, cleanup may
enter the still-existing namespace and remove only the same recoverable peer. A
missing namespace and host pair is already absent. Same-named foreign state is
never removed.

This slice creates no route, neighbor entry, sysctl, BPF attachment, or loopback
change. Netkit remains unsupported and separately gated.

## Alternatives

Names alone cannot distinguish stale owned state from a foreign collision.
Aliases alone are not sufficient because kernels do not guarantee their
application in the atomic veth-create request; deterministic hardware addresses
provide the creation-time recovery marker. Moving an async runtime worker into a
namespace risks contaminating later operations. Forking `ip` obscures typed
errors and makes ownership validation dependent on command output. Completing
ADD before routes would violate the usable-network result contract.

## Verification

`make cni-veth-test` runs unit tests and strict lint, builds the lifecycle
example, creates a dedicated real Linux network namespace, and executes the
typed production API with elevated network capability. It verifies dual-stack
application, exact independent readback, replay, removal of both managed
addresses, cleared aliases and down links followed by complete reconstruction,
first and repeated deletion, and absence of both endpoints. It then creates a
foreign same-named dummy and requires both apply and delete to reject it while
the dummy remains intact. Exact temporary resources are removed by a trap.

## Consequences

Milestone 6.4 is Verified as a portable local link primitive. ADR 0063 now
composes it with native routing and durable allocation in the atomic CNI
lifecycle. Existing overlay installations remain unchanged until isolated
primary-CNI cluster qualification passes.
