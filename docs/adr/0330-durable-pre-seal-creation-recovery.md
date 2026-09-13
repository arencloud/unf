# ADR 0330: Durable Pre-Seal Creation Recovery

Date: 2026-09-13

Status: verified locally; cl02 and matching Kind qualification pending

## Boundary

ADRs 0327–0329 bind Pod UID to CNI ownership and qualify normal lifecycle
recovery, but deliberately cannot adopt an existing unaliased veth using only
its legacy name and MAC. A process interruption between kernel creation and
alias sealing therefore remains fenced. This slice adds evidence specific to
one creation attempt, without weakening checks on Ready workload endpoints.

## Durable creation nonce and compatibility

Schema-4 Prepare generates one nonzero, unique 256-bit nonce from the OS CSPRNG
for a UID-bound attachment and persists it before returning the attachment.
Replays and restart retain the same nonce. Normal completed deletion/abort
followed by a new Prepare generates a different nonce, even for a reused key,
UID and address. Failed persistence restores the prior journal state. The nonce
is public uniqueness metadata, not a credential, signature or encryption key.

Transactions 2 and 3 remain supported only for records they can understand:
v2 cannot access UID bindings; v3 cannot access creation nonces. No field is
stripped to make an old reader accept new authority. Supported older requests
receive readable errors in their requested version, without any new record
authority. Old v3 Prepare requests
still create their original UID-only records. New clients require a v4 agent.
Journal schemas 2 and 3 open without rewriting or changing their markers;
only records with new creation nonces require journal 4. Unbound-only state
still writes schema 2, and UID-only state writes schema 3. Schema-1 migration
remains unbound. Zero/duplicate nonces, a nonce without UID, and nonce fields in
older journal formats are rejected. The single-record response is boxed in
Rust to keep the enlarged success variant off the error-path stack; JSON is
unchanged apart from the explicitly versioned new field.

## Kernel evidence and recovery

For new nonce-bearing records, domain `unf.cni-workload-owner.v3\0` hashes the
nonce and complete network/container/interface/UID coordinate. The digest
provides two distinct locally administered unicast MAC markers (45 bits each)
and an independent temporary-peer name (48 bits). These 138 public fingerprint
bits are not a signature or a packet permission. Full digest/role aliases are
set and independently read back before normal attachment completion. Legacy
v1 and UID-only v2 aliases/MACs retain their existing interpretation.

Recovery requires the durable nonce, a non-Ready lifecycle record, and the exact
reciprocal, down host/temporary-peer pair still in the host creation namespace.
Names, MACs, MTU, indices, reciprocity and any existing aliases must match before
missing aliases are sealed. A fully sealed pair can resume normal progression
after host-up. Ready, moved, foreign or marker-mismatched endpoints cannot be
reclassified as an interrupted creation. Preparing deletion and abort cleanup
use the same narrowly scoped check. Existing UID-only unaliased records do not
gain a nonce retrospectively and remain fenced.

This assumes integrity of the root-owned journal and trusted host/runtime, as
does the existing root-authenticated CNI transaction service. It does not claim
protection against a privileged host actor forging all public kernel markers,
zero collision probability, packet-time ifindex-reuse safety, route immutability
or authenticated controller placement. Those are separate L3 prerequisites.

## Qualification

Unit regressions cover nonce persistence/replay, uniqueness after retirement,
v2/v3 refusal, v3 marker preservation, malformed persisted nonces and marker/
lifecycle separation. The expanded isolated production CNI qualifier constructs
interrupted kernel states from a durable Prepare: unsealed pair, peer-only seal,
fully sealed host-up pair, and deletion from unsealed Preparing. Resume must
retain the exact nonce and host index; no recreation is allowed to fake recovery.
It retains the earlier UID/alias/dual-stack-route/reuse checks and adds a wrong
UID rejection before sealing, for twelve negative checks.

All 784 workspace tests pass (26 privileged/environment-specific tests remain
ignored); workspace/all-target/all-feature Clippy passes with warnings denied,
as do formatting and qualifier shell syntax. Verification used a serial,
isolated `/tmp` Cargo target with two build jobs and debug symbols disabled.
Earlier overlapping-build and Btrfs metadata-reservation stalls are retained as
workstation failures, not product passes. No filesystem repair or broad cleanup
was performed; disabling debug symbols did not disable assertions or features.

The order remains local checks, then cl02, then matching retained Kind,
with complete diagnostics and UNF log reviews. Neither live CNI installation,
encryption generation, BPF map nor release pin is changed by this source slice.
Full locality consumption, live rollout, L4/L5/Q and S1–S5 remain open.
