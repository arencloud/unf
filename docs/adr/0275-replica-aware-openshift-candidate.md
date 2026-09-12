# ADR 0275: Replica-aware OpenShift candidate

Date: 2026-09-12

Status: Deployment and initial Required migration verified; fixture convergence failed

Runtime `7f1cc64304c39ee843c64a5462d46c78df58efed` adds ADR 0274's exact
assignment-bound replica receipt join to the bounded proof-exchange runtime.
The Phase 9 release record and Kustomization pin its immutable public controller
and agent images; test-tools are unchanged. Kind remains explicitly pending.

The full workspace passed 723 tests with 22 privileged tests excluded by the
generic invocation. Strict all-target/all-feature workspace Clippy passed.
A prepublication encryption rerun passed 107 tests with two privileged tests
excluded; formatting, the OpenShift static gate and the redacted recent-commit
secret scan passed. No new compression backend or recovery format is included:
the inconclusive experiment is recorded in the stabilization plan.

Deploy to cl02 preserving Node-local authority, then run the complete Required,
selective, ciphertext, failure, rotation, replacement, operations and cleanup
gate at the existing 2-GiB controller limit. Record the six pre-existing unhealthy
operators without presenting them as a healthy baseline. Archive exact runtime
and harness evidence; only a complete cl02 pass permits successor Kind testing.
The transient checkpoint-size gap is unresolved and must not be hidden by a
successful traffic result. Phase 9 and heavy-load stabilization remain open.

## cl02 result

Harness `f4ec73c` passed preserved-state deployment of the exact runtime with all
five agents converged. Archived deployment evidence SHA-256 is
`cf8e4997c12543171bc09ca38d781bc1c3409cb30ccbdac3a8542c48acf0885f`.
The full gate passed initial Native-to-Required migration and created all four
Ready traffic fixtures, but timed out waiting for the post-fixture generation
at line 566. No ciphertext, selective, failure or later recovery pass is claimed.
The gate collected diagnostics, requested Native restoration and removed its
reserved namespaces; successor Kind remains pending.

Agents reported repeated active/pending probe rendezvous timeouts and deferred
key catch-up while an older epoch drained. A concrete retry-lifecycle gap remains:
the socket responder survives successful local completion, but a timed-out
exchange closes it before the authenticated round expires. A peer starting
outside the four-second local attempt cannot use that endpoint's responder.
This needs a delayed-peer regression; it is not yet proven to explain every
fixture or rotation failure.

One Required controller cgroup sample peaked at 361,340,928 bytes with zero OOM
events at the unchanged 2-GiB limit. The compressed checkpoint overflow recurred
at 911,814 bytes; 35 persistence errors were later observed before a smaller
790,676-byte payload fit. These are lab diagnostics, not a heavy-load benchmark
or a resolution of the persistence gap.
