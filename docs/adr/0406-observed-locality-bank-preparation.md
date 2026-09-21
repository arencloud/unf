# ADR 0406: Bounded Observed Locality Bank Preparation

Date: 2026-09-21

Status: locally verified; complete disposable cl02-before-Kind gate pending

## Decision

`unf-locality` now joins independently replayed locality placement to opaque
`NativeAttachmentObservation` objects. These objects can only be obtained from
real descriptor-bound link/route observations. Canonical bank preparation keeps
one endpoint per attachment and one index per admitted address, with full UID,
creation nonce, ownership aliases and observed namespace coordinates. It rejects
duplicate keys/nonces/addresses/devices, foreign context, retired observations
and exact-address owner substitutions. Peer indexes are namespace-relative;
several interfaces may share a namespace cookie without that cookie alone being
treated as an endpoint identity. It never expands source/destination pairs.

`bind` compares freshly supplied applied context and the exact real journal cut
and records before issuing ADR 0403's nonce/serial leases under the transaction
lock. Gate registration must match even for an empty bank. Failed binding does
not return a partial bank. A lease or preparation is **not** a loaded program or
packet permission, and gate entries alone cannot authorize delivery.

### Bounded observation and cancellation

The new batch route APIs stream the host route/neighbor tables once for the
selected cohort. They retain expected keys and seen bits, not unrelated host
messages, and reject duplicate, missing or conflicting selected entries. Peer
tables are streamed in each retained namespace. Bank rechecks also use one host
scan and retire the entire cohort before the first await. Failure/cancellation
cannot leave part of the preparation looking current; restoration needs a new
observation. Existing single-attachment CNI route lifecycle APIs are unchanged.

Bounds are explicit: 65,536 attachments, 131,072 selected route/neighbor keys per
table, 1,048,576 messages and ten seconds per namespace route snapshot. Peer
link observations gain an observation-only ten-second deadline. These limits
reject work; they do not silently drop evidence or relax packet enforcement.
The indexed scan is structurally proportional to streamed messages times
log(selected keys), rather than repeated full host dumps per attachment. No
CPU/RSS/throughput benefit is claimed without measurement.

`LocalityObservationWorker` retains one job permit through its private runtime's
actual nested-worker shutdown. Dropping the public task signals cooperative
cancellation, not an early permit release. A sixty-second total observation
deadline and ten-second namespace-leaf deadlines bound normal cancellation
drain. A queued task may be aborted; a started namespace thread must finish.
The publisher must keep one worker across candidate retirement, not replace
its semaphore during churn. Record input has a 16 MiB logical payload budget;
this is not an allocator or RSS bound. No CNI lock is held during observation.

### Namespace coordinates

The veth observer queries `SO_NETNS_COOKIE` on the same owned host/peer netlink
sockets used for readback, adding no socket or namespace thread. A narrow
checked Linux ABI wrapper verifies syscall result, exact 8-byte width and
nonzero values; host and workload namespaces must differ. Recheck compares the
original cookies and retires them with the held descriptors on failure.
Ordinary CNI CHECK does not collect cookies or require this socket option.
Linux 5.14's [generic socket dispatch](https://raw.githubusercontent.com/torvalds/linux/v5.14/net/socket.c)
and [socket option implementation](https://raw.githubusercontent.com/torvalds/linux/v5.14/net/core/sock.c)
establish the netlink-socket ABI basis. Live independent UDP-cookie parity is
required on both deployed kernels, not inferred solely from this source audit.

## Verification and next boundary

All 863 workspace tests pass (26 privileged ignored), with strict all-target
Clippy, formatting and shell syntax checks. New tests cover streaming bounded
retention through 40,000 unrelated messages, duplicate/missing/foreign keys,
unbound metadata, cookie decoding, address-family/UID/context joins, payload
limits, and cancellation/early-error worker draining. Evidence logs are
`.artifacts/p9-{batched-cookie-tests,observed-bank-tests,observed-worker-tests-2,observed-bank-workspace-2,observed-bank-clippy-6}.log`.

The disposable immutable fixture regresses all 28 existing native-observation
cases, then uses actual temporary CNI journals/links/routes, independently
replayed fixture placement, the bounded worker and kernel gate to prepare two
endpoints/four addresses. It checks independent UDP/netlink cookie parity,
aliases, route-drift/cancellation retirement, stale applied context/journal
rejection and scoped revocation. The fixture sends no workload traffic and
touches no production CNI journal or pin. cl02 must pass before matching Kind.

The live agent does not yet consume this new library. Next integrate frozen
device maps/private seeds, the immutable program publisher and policy-first
packet path, with current-context/journal fences and restart migration. The
worker's budget must cover that complete preparation lifecycle. Same-Node and
mixed-replica delivery, packet-time route/lifetime proof, L3/L4/L5/Q and Phase 9
remain open. Release pins, live packet behavior and admission claims are unchanged.
