# ADR 0275: Replica-aware OpenShift candidate

Date: 2026-09-12

Status: Candidate; full cl02 and successor Kind qualification pending

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
