# ADR 0285: Live Admitted Encryption Fault Targets

Date: 2026-09-13

Status: qualifier repair implemented; full cl02/Kind qualification pending

## Observed boundary

Runtime `cb59e90`, qualifier `1e37477`, passed the stricter five-Node Required
migration and persistence checks on cl02. It then passed convergence after
fixture creation, Required-baseline IPv4/IPv6 PodIP and ClusterIP traffic,
selective-mode convergence and the corresponding Required/Native traffic checks.
The full gate failed at the beginning of `ciphertext-and-fail-closed` because
the test selected nonexistent interface `unfwg00000000bf` (epoch 411).

A nearby saved selective frontier named epoch 412 and `unfwg00000000bg` as active
on both workers. Recovery plans are sorted by epoch; the qualifier incorrectly
used `active.plans[0]` as a live fault target. The first entry can be a draining
predecessor, and a retained journal entry does not prove a device still exists.
No packet-capture or fail-closed result is claimed from this failed run.
After fixture removal, public captures showed zero-transport Native plans on
all five Nodes with a newer Native generation pending. This is not final exact
cleanup qualification. Phase 9 remains open.

## Decision

Both platform gates use one shared live-target selector and mutation guard.
Join current netlink devices to retained active/pending plan metadata and exact
transport interface indexes. Require one or two owned WireGuard devices,
including the active epoch. Match the full cluster/Node UID/epoch ownership
alias, not only a prefix; preserve foreign devices. Accept the runtime's actual
fixed-width base-36 names, including alphabetic digits after early epochs.

Refresh the bounded target set before each outage probe so natural rotation
cannot silently move the test onto an unaffected successor. Immediately before
each link change, independently recheck interface name, index, exact alias and
WireGuard kind on the Node. Register cleanup before mutation so a lost command
acknowledgement cannot leave an untracked fault. Restore only that exact device;
a positively absent or replaced original target needs no restoration, and its
replacement is never raised by name alone. Attempt owned restoration before
collecting potentially slower failure logs.

The fault is still a temporary test-owned link outage, not a runtime networking
change. No keys or journals are mutated by target selection. A race or identity
mismatch refuses the operation; it does not waive traffic, ciphertext, complete
generation, or recovery assertions. No lifecycle convergence deadline is raised.

## Verification

`bash hack/verify-phase9-link-fault.sh` covers a retired first plan with a live
successor, simultaneous active/draining targets, alphabetic base-36 names,
foreign identity/alias/kind, changed interface index, missing active authority,
positive retirement, failed netlink queries, actual host-side JSON projection,
command quoting and deduplicated cleanup. Netlink is mocked in these local
tests; they change no host or cluster interfaces. Both platform static gates
invoke this regression suite. Live qualification must rerun on cl02 first,
then Kind, against the unchanged digest-pinned `cb59e90` runtime.
