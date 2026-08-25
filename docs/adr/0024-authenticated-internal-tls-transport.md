# ADR 0024: Authenticated internal TLS transport

Status: Accepted and live verified for controller-agent transport

## Context

ADR 0023 bound agent acknowledgement claims to short-lived Kubernetes Pod
credentials, but the controller exposed snapshots, acknowledgements, and flow
telemetry on one plaintext Service port. That leaked bearer credentials and
desired-state data to any workload able to observe the connection. Snapshot
reads and telemetry writes were also anonymous.

The operator API must remain easy to probe and port-forward, while bearer-token
traffic needs an encrypted, authenticated boundary with deterministic trust.

## Decision

The controller has two listeners:

- port 9962 is the public HTTP operator surface for health, metrics, status,
  topology, history, explanation, and simulation;
- port 9964 is the internal HTTPS surface for identity/policy snapshots, agent
  acknowledgements, and flow telemetry.

Agent-only routes are not registered on the public router. Connected controller
mode refuses to start if its server certificate or private key cannot be loaded.
Offline development mode starts only the public listener.

Agents require an `https://` controller URL and build one Rustls client that
trusts only the CA mounted at `/var/run/secrets/unf-internal-ca/ca.crt`; ambient
native and WebPKI roots are excluded. Every internal request rereads the
automatically rotated projected token and sends it as a bearer credential. The
controller TokenReviews new credentials and keeps at most 64 successful results
for 30 seconds to bound Kubernetes API load. Invalid credentials are never
cached. Every request, including cache hits, revalidates the returned Pod name/UID
against watched state and authorizes acknowledgement and telemetry Node claims
against authoritative Pod placement.

The agent treats the HTTPS URL's TCP port as reserved controller-management
traffic. Events whose source or destination uses that port are counted by
`unf_management_flow_events_filtered_total` but excluded from workload logs and
flow export. This prevents snapshot/export traffic from recursively creating more
telemetry and crowding workload evidence out of bounded buffers.

The deployment contract expects:

- Secret `unf-internal-tls` containing `tls.crt` and `tls.key`; and
- ConfigMap `unf-internal-ca` containing `ca.crt`.

The disposable kind workflow creates a private development CA and DNS-valid leaf
certificate below ignored `.tools/kind-internal-tls/`, then applies those two
objects before workloads. Private key material is never committed. Production
installers must integrate with their approved certificate issuer instead of
using the development CA.

The OpenShift overlay satisfies the same contract with the Service CA operator:
the Service requests Secret `unf-internal-tls`, an annotated ConfigMap receives
`service-ca.crt`, and the agent volume maps that key to its portable `ca.crt`
path. No OpenShift-specific TLS behavior exists in the binaries.

## Verification

Unit and static gates compile the Rustls-only server/client configuration and
render both Service ports and certificate mounts. The two-node kind gate requires
all agents to converge and export retained flows through HTTPS, proves agent-only
routes are absent from plaintext port 9962, rejects TLS without the dedicated CA,
rejects missing and invalid credentials, accepts a real projected Pod token for
snapshot reads and acknowledgements, and rejects a forged Node claim.
The OpenShift IPv4-only and dual-stack gates repeat those boundaries with a
platform-issued serving certificate, validate its DNS SAN and injected CA, and
prove real projected tokens and cross-Node rejection under OpenShift TokenReview.

## Consequences

Bearer credentials, snapshots, acknowledgements, and flow telemetry are encrypted
in transit and authenticated without introducing static client secrets. Server
TLS plus Pod-bound TokenReview is the selected equivalent encrypted boundary;
client-certificate mTLS is not required for this phase.

ADR 0026 extends this boundary with validated in-place serving-keypair and
CA-bundle reload. Issuer changes use an overlapping trust bundle; malformed
updates retain the last-known-good configuration without a process restart.
Durable acknowledgement/history retention, issuer-specific production
automation, and NetworkPolicy isolation of the internal port remain separate work. A
successfully reviewed token may remain accepted for up
to 30 seconds while its Pod still exists at the same authoritative placement.
Applications intentionally using the reserved controller TCP port are outside the
workload telemetry surface for that agent configuration. OpenShift Service CA
issuance, projected tokens/TokenReview, SCC/SELinux admission, and the encrypted
Service path are IPv4 and dual-stack live-verified. The separate rotation gate
proves external-PKI handoff and Service CA restoration without Pod replacement.
