# ADR 0020: Physical policy map pressure and rollback

Status: Accepted for Phase 2 transactional failure validation

## Context

The policy compiler and agent reject snapshots larger than one logical bank, and
unit tests cover those bounds. That does not prove the runtime behavior when the
kernel itself rejects an insertion into a physically full pinned map. Policy
activation spans three staging maps and must leave the selected bank, applied
revision, and forwarding behavior unchanged if any pre-switch write fails.

A useful integration test must create real pressure without colliding with
compiler-produced keys, must keep pressure present while the agent rolls staging
state back and retries, and must clean up without deleting legitimate entries.

## Decision

The disposable kind verifier uses a small test-only BPF syscall helper from the
existing privileged fault DaemonSet. On the server node it reads the selected
policy bank and inserts reserved synthetic keys tagged for the inactive bank into
the real shared `POLICY_RULES` map until `BPF_MAP_UPDATE_ELEM` returns the
kernel's capacity error. Synthetic keys use source identity zero, which the
identity registry reserves, plus a fixed marker and bounded sequence. The helper
uses `BPF_NOEXIST` and continuously refills its key set while pressure is held
because the agent's rollback removes inactive-bank entries before its next retry.

While pressure is held, the verifier changes the native policy from Enforce to
Shadow and requires all of the following on the pressured agent:

- desired policy revision advances;
- applied policy revision and selected bank remain unchanged;
- `unf_policy_sync_errors_total` increments and logs identify staging failure;
- the previously allowed TCP/8080 flow remains allowed; and
- the previously denied TCP/9090 flow remains denied.

The verifier then signals the helper to stop. Cleanup deletes only the known
reserved synthetic keys. The agent must apply the same waiting revision on the
opposite bank, Shadow traffic must pass, and a final Enforce update must converge
and restore the deny. Normal trap cleanup repeats scoped key removal if the test
exits early. The helper image and DaemonSet remain test fixtures and are not part
of the production kustomization.

## Consequences

Phase 2 now has live-kernel evidence for the physical insertion-failure path in
addition to logical capacity bounds and isolated startup corruption rejection.
The test proves pre-switch rollback preserves last-known-good forwarding and
that retry makes progress after the external pressure is removed.

This does not validate operating-system-wide memory pressure, failures in every
individual map type, the legacy netlink attachment path, or OpenShift security
constraints. Those remain separate hardening work.
