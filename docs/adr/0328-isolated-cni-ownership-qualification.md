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
