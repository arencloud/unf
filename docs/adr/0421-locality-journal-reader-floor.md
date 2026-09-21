# ADR 0421: Durable locality journal reader floor

Date: 2026-09-21

Status: implemented; cl02-first immutable qualification pending

An older CNI server must not mutate attachments while a newer locality consumer
continues referencing them. A versioned BPF path alone does not protect this:
the agent currently starts CNI before loading the dataplane. Add journal schema
5 as a durable requirement for retirement-aware readers. The transaction wire
protocol remains version 4; this is an explicit journal compatibility boundary,
not a reinterpretation of its existing attachment or nonce layout.

`install_required_retirement` first installs the fresh process-local callback,
then durably commits the schema-5 reader floor before returning a registration.
`IncarnationGate::install` uses this operation before any lease can be issued.
Existing attachment records, addresses, nonces and provider provenance remain
unchanged. Unbound/legacy records gain no new authority. Empty inventories retain
the reader floor; deleting the last bound record cannot silently downgrade it.
The optional snapshot-only retirement API remains unchanged for non-publishing
callers; a previously guarded document always retains its requirement.

Reopening schema 5 restores neither callback nor permission. It exposes no
publication cut and rejects CNI requests until a fresh hook is installed.
Failures during floor persistence invalidate the cut and return no registration;
the unpublished map/callback remains owned until journal close. Stop startup,
not retry installation or issue permission. A failed write may have renamed the
new document, so the in-memory requirement is conservatively retained.

Old schema-4 readers reject schema 5. This does **not** withdraw old kernel maps,
prove a startup fence or authenticate restored placement. New production startup
must first withdraw all previous locality authority, then install the fresh
journal gate, and only then mutate routes or serve CNI. Never manually lower the
schema to make a rollback start; a safe downgrade requires independently proved
removal of the newer packet authority and an explicit supported migration.

Three regressions cover exact record preservation, reopen/no-hook denial,
fresh registration, empty/legacy retention and failed upgrade. The diagnostic
adds the frozen production `45d85d5` agent from its immutable image. In the private
fixture it receives no controller, BPF object, uplink, host mount or inherited
credentials. A ten-second bounded invocation must fail specifically on the
5-versus-4 schema check before creating its private socket/readiness lease,
with journal bytes unchanged. This tests the actual old executable, not a
simulated old reader. All native/bank/coordinator/socket cases remain mandatory.

All 894 workspace tests pass (26 privileged tests intentionally ignored), as
does strict workspace all-target Clippy. Formatting and shell syntax pass.
Evidence: `.artifacts/p9-journal-floor-workspace-{test,clippy}.log`.

No production journal is upgraded by this implementation or diagnostic. Full
agent startup integration, applied writer hooks, packet composition, restart
continuity and L3/L4/L5/Q remain open. Qualify the complete immutable
`kernel-journal-floor` suite on cl02 before identical-image Kind.
