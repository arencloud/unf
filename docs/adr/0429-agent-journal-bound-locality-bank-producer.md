# ADR 0429: Agent journal-bound locality bank producer

Date: 2026-09-21

Status: implemented and locally verified; production qualification pending

The actual agent placement cache now owns a persistent single-slot observation/
preparation worker and a three-stage journal-to-kernel publisher. It observes
only the selected real Ready UID/nonce-bound CNI records, binds leases under
the actual CNI transaction mutex, seals off the event loop, and publishes under
that same journal mutex and the applied-writer coordinator. Every handoff uses
fresh applied placement coordinates and the **original** journal cut. A newer
cut never salvages stale work. Publication retains the bank before any further
fallible operation or await.

Candidate replacement, errors and teardown withdraw active selection. Cancelling
a preparation does not replace the worker or release its capacity before actual
joined namespace work drains. No slow observation/seeding holds the CNI mutex;
only bounded metadata, lease binding and final publication do. Empty inventory
does not manufacture an empty permission bank.

Cache reuse checks the actual selected kernel program and fence, not merely
matching revision numbers. A writer can withdraw and successfully reapply the
same coordinates; only explicit revalidation/publication can select a bank
again. The expanded isolated coordinator diagnostic tests that distinction.

The native observer additionally supports each managed record's own MTU with
one streaming host-table scan. The former uniform-provider API remains strict.
The combined diagnostic now uses real 1400/1450-byte attachments, rejects the
wrong uniform provider, and exercises all existing bank/socket checks with
those different MTUs. New agent regressions reject full-context drift, foreign
journal instances, changed placement digests and journal delete/recreate ABA.

Production packaging includes the separate locality consumer ELF next to the
main object. The agent opens it without following the final symlink, checks
root ownership/type/mode, bounds the read to 4 MiB plus one overflow byte and
initializes a managed preparation directory before packet attachment. Boundary
image builders carry both artifacts. This does not overwrite release pins or
the retained `45d85d5` live baseline.

Limitations remain explicit: this producer is not yet called by production
packet dispatch; status continues to report no kernel-admitted/delivery claim.
Pure-local Required demand, key-churn-independent placement reuse, policy/
Service/egress/reverse-path composition, crash-stage resource cleanup and
restart continuity still require integration and actual runtime qualification.
The expanded isolated diagnostic must pass cl02 before identical-image Kind;
it cannot qualify the whole actual publisher or applied writers. L3/L4/L5/Q
and stabilization remain open.

Local validation: 908 workspace tests pass, 26 explicitly ignored; strict
workspace/all-target Clippy, workspace formatting and shell syntax checks pass.
