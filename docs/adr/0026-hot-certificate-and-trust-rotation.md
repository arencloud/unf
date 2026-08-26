# ADR 0026: Hot certificate and trust rotation

Status: Accepted and live verified on OpenShift

## Context

ADR 0024 introduced a CA-pinned HTTPS boundary for controller-agent traffic, but
both sides loaded TLS files only at startup. OpenShift Service CA renewals and
external-PKI issuer changes therefore required coordinated workload rollouts.
That couples routine credential lifecycle to dataplane process replacement and
creates avoidable availability risk.

Projected Secret and ConfigMap volumes update through atomic filesystem swaps.
Reload logic must detect those swaps, tolerate propagation delays between files
and Nodes, and never replace working TLS state with partial or malformed input.

## Decision

The controller reads its serving certificate and private key at startup, then
compares their contents every five seconds. When either changes, it constructs a
complete Rustls server configuration before atomically replacing the active
configuration. New connections use the new keypair; existing connections may
finish on the prior configuration. Read or validation failures increment
`unf_controller_tls_reload_errors_total` and retain the last-known-good server.
Successful replacements increment `unf_controller_tls_reloads_total`.

Each connected agent owns a shared CA-pinned HTTP client. Before every snapshot,
acknowledgement, or telemetry request, it rereads the mounted CA bundle and
compares the bytes with the last observed version. A changed bundle must contain
at least one parseable PEM certificate before a replacement client is published.
Invalid content is remembered to avoid a retry/log storm while the active client
continues using last-known-good trust. Success and rejection are exposed through
`unf_agent_controller_trust_reloads_total` and
`unf_agent_controller_trust_reload_errors_total`.

Issuer changes use this order:

1. publish a CA bundle containing both old and new roots;
2. wait until agents have accepted the overlap;
3. replace the controller leaf/keypair with one signed by the new root;
4. verify authenticated agent traffic and convergence;
5. remove the old root from the bundle.

Leaf renewal under the same issuer needs only step 3. The binaries remain
platform-neutral: Kubernetes/external PKI uses `ca.crt`, while the OpenShift
overlay maps its injected `service-ca.crt` to the same path.

## Verification

Unit tests prove plaintext controller URLs fail before trust loading, valid PEM
bundle changes replace the agent client, and malformed changes are counted once
while retaining the existing client. Workspace formatting, lint, and tests gate
the implementation.

`make openshift-tls-rotation-test` records the live certificate contract and Pod
UIDs, disables Service CA reconciliation only for the bounded test, generates a
temporary external CA and DNS-valid leaf, and exercises the full overlap and
contraction sequence. A projected Pod token reads an authenticated snapshot under
the new issuer. The gate injects malformed CA and leaf values, requires rejection
metrics plus continued convergence, reverses the overlap, restores the original
OpenShift objects and annotations, and requires every Pod UID to remain unchanged.
An exit trap restores Service CA management after any failure.

## Consequences

Routine leaf renewal and planned issuer rotation no longer require controller or
agent replacement. Partial projected updates fail closed with respect to new
material while preserving the already authenticated channel. CA bundles can
contain multiple roots during a bounded overlap, but ambient host/WebPKI roots
remain excluded.

The mechanism does not choose renewal times, request certificates, or define a
production issuer policy. Operators must provide an overlap window long enough
for every node to project and accept the bundle before switching the leaf, and
must monitor reload-error counters. ADR 0027 provides bounded durable
acknowledgement checkpointing; durable flow-history retention,
internal-port NetworkPolicy, and issuer-specific production automation remain
separate work.
