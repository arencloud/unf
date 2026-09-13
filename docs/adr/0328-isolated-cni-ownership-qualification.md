# ADR 0328: Isolated CNI Ownership Kernel Qualification

Date: 2026-09-13

Status: isolated cl02 kernel gate verified; matching Kind execution pending

`hack/verify-cni-workload-ownership.sh` invokes the production CNI orchestration
through its existing disposable-journal adapter. Each invocation reopens the
journal, exercising independent process restart. The dedicated development
test image embeds the compiled adapter and qualifier, records the source commit
as an OCI label, and uses the immutable existing test-tools base image.

Execution is restricted to an explicitly acknowledged privileged qualification
container. Two uniquely named network namespaces contain all test links, routes
and neighbors; no host paths, live journals, BPF maps or CNI installation are
mounted or modified. The temporary journal remains with diagnostics. Namespace
cleanup failures fail the run even if the assertions previously passed.

The gate checks legacy replay without rebinding, durable Pod UID and kernel
aliases, restart, changed/omitted/duplicate UID rejection, missing/legacy alias
rejection without journal mutation, IPv4/IPv6 route-loss rejection, exact
recovery, normal deletion and same-address reuse by a different Pod UID. Eleven
negative checks must fail with structured CNI errors. Normal cleanup must prove
empty journal, absent endpoints and absent owned routes in both IP families.

The final JSON names the binary SHA-256 and deliberately records
`liveLocalityAdmission:false`. This is not authenticated controller placement,
generation/map publication, a packet-time ifindex-reuse defense or an L3/L4/L5
locality dataplane pass. Qualification must run on cl02 before the identical
test image on retained Kind, with UNF logs inspected around both runs. No live
runtime image is rolled forward by this isolated qualifier.

Bash syntax validation passes. ShellCheck is not installed on the workstation;
no ShellCheck pass is claimed. Platform evidence will be added after execution.
The first image build compiled the adapter but refused to copy the qualifier:
the container context excludes `hack/`. The context now admits only this exact
qualifier script; credentials, tools, prompts and other harnesses remain excluded.

The first cl02 attempt stopped before Pod creation on pre-existing namespace
security labels; its owned namespace was removed. The wrapper now explicitly
updates those labels only on its newly created namespace. The next attempt
passed legacy replay, then failed the UID-bound ADD. Its command-substitution
boundary did not retain the CNI JSON error, so the cause is not yet attributed.
The qualifier now retains and prints the last CNI response on failure. Both
attempts remain failures; no Kind test or live runtime rollout has occurred.

The retained rerun (`80335a1`) attributes the failure to missing host
`IFLA_IFALIAS` immediately after successful veth creation. Strict alias fencing
correctly refuses both adoption and generic rollback. The repair adds a
creation-only seal after successful exclusive `RTM_NEWLINK`: read back the
down, exact reciprocal host/peer pair, set both aliases, read them back again
and require stable indices. Existing-link recovery cannot use that permission.
Zero/reused indices, broken reciprocity, changed addresses, an up endpoint or
foreign aliases fail the creation checks. A crash before sealing still leaves
unproven state fenced; automatic recovery of that boundary is not claimed.
Focused CNI/link tests and strict Clippy pass for the seal repair. Negative
qualifier checks additionally require the expected UID, alias or incomplete
host-route diagnostic, not just a generic CNI failure code.

## Verified cl02 result

The repaired image first passed every in-container assertion, but the outer
reader rejected the multi-line JSON result. That attempt remains an observer
failure. The reader now parses one complete JSON document, requires a nonempty
result and the successful cleanup trailer, and retains the private fixture
archive before deleting the owned namespace. A complete fresh cl02 rerun passes.

- Source: `d3207e37d4da861b856db30a0784835b99f8d7cb`.
- Test image: `quay.io/arencloud/unf-test-tools-dev@sha256:c56c2c3e9a06fc6333b8b4bacee969346488241ab9a0cc479677e7ba51d66d7d`.
- Adapter SHA-256: `892e6117910ff3c9d432f00c41308e48593ff098ac1f55a0b6ac1ec39fd02308`.
- Result JSON SHA-256: `e0964143dcb854b25fa05ac94be792dd8b5010281f07a85255d284966e962a83`.
- Fixture archive SHA-256: `68f97adf60375b6c6e8dc49c24dffc888d765b7316e5398d85ab84a5e5bdfff5`.

The exact worker UID is preserved on `bc-24-11-27-b6-49`; RHCOS 9.8,
kernel `5.14.0-687.39.1.el9_8.x86_64`, CRI-O 1.35.6. The tokenless privileged
fixture was admitted under the existing `node-exporter` SCC. It had no host
mounts and zero restarts. All eleven negative assertions and positive lifecycle
checks pass, and the owned test namespaces are absent after cleanup. No live
UNF attachment, image, journal or BPF map was changed. The full source workspace
passes 779 tests, with 26 explicitly ignored; strict workspace Clippy passes.

Before/during/after controller, five-agent and installer log reviews find no
ERROR/panic/OOM/verifier failure in their bounded windows. All UNF containers
remain Ready with zero restarts. The final 20-minute window retains 406 flow
history warnings, 43 peer-proof-assistance warnings and eight topology history
warnings. These remain operational/stabilization findings, not a clean-history
claim. No log file in these windows reaches the configured tail/byte cap.

Next: the identical isolated image on retained Kind. This does not close L3's
interrupted-creation recovery, authenticated placement/route binding, versioned
map distribution or packet-time locality admission, nor L4/L5/Q or S1–S5.
