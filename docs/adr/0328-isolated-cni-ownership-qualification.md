# ADR 0328: Isolated CNI Ownership Kernel Qualification

Date: 2026-09-13

Status: qualifier implemented; cl02 and Kind execution pending

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
