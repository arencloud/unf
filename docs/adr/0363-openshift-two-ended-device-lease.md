# ADR 0363: cl02 Two-Ended Device Lease Delivery Gate

Date: 2026-09-14

Status: verified for the isolated serial delivery mechanism; Kind pending

Source `5f553c3` passes the complete disposable cl02 gate on immutable image
`quay.io/arencloud/unf-test-tools-dev@sha256:0a8dffc8dca0edbf1f24ef8425e579aeb94b485f73a23414a1fdf033f9e0962a`.
Anonymous inspection verifies the complete source label. Diagnostic object
SHA-256: `e0f7381b1bd9b729c678ffb507e640bee3a28af8b37f2e7b4102af7db1176037`.
The first down-interface receiver failure is retained in ADR 0362.

At 00:46:07 UTC the complete IPv4/IPv6 matrix finishes with sixteen exact
application deliveries and fourteen denied attempts. Each denial has an armed
receiver, the expected timeout and empty payload. Thirty exact map readbacks
separate eighteen requested redirects from twelve classifier rejections: two
requests do not deliver while the peer is administratively down. A redirect
request is not treated as proof of delivery.

Host rename preserves delivery. Moving either peer into a foreign namespace
is rejected by that endpoint's cookie check; return to the original namespace
restores the serial positive control. Moving the target host invalidates its
device-map binding; returning it does not rearm delivery. Deleting/recreating
the target with the same host/peer indices and MACs likewise remains denied.
Explicit binding and context reseeding are required for both recoveries. Invalid
configuration is denied and valid configuration recovery is checked separately.

The RHCOS receiver retains its IPv4 address but loses IPv6 addresses when down;
before/after address inventories confirm the first fixture failure's cause.
Wildcard namespace-scoped receivers allow the negative test to remain armed.
Receiver RPF settings are 0/0; no RPF or address-retention sysctl is changed.
The two programs are accepted by the kernel (translated/JIT bytes: redirect
5,288/3,372; seed 3,272/2,075). These sizes are not performance measurements.

Evidence: `.artifacts/p9-device-lease-5f553c3-cl02`; raw archive SHA-256
`a5399e8c076a582ccac9b24b99aff1f42288710892f38bbeb94549812c24aa94`.
No target kernel pointer is exported in results. All owned namespaces, private
attachments/maps/bpffs and the Kubernetes fixture Namespace are removed. Node
UID is preserved. All five live UNF reports are fresh/converged at policy 468 /
Service 203, with Ready/zero-restart containers. Live runtime remains `f984db9`.

Controller, every agent and installer logs are reviewed before/final, with the
final window covering traffic and cleanup. It includes 415 bounded flow-history
warnings, 28 proof-assistance warnings and four topology-history warnings, with
no live UNF ERROR, panic, OOM or verifier rejection. Warnings remain findings.

This is a serial mechanism gate, not authenticated locality admission, concurrent
lifetime proof or measured scalability. The boundaries in ADR 0362 remain:
address/UID/nonce binding, immutable publication/retirement, host-down semantics,
policy/Service/egress composition and production integration are open. The same
immutable fixture must pass retained Kind next. Full Phase 9 and S1–S5 stay open.
