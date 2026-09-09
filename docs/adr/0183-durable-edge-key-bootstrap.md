# ADR 0183: Durable Edge-Key Bootstrap

- Status: Accepted and implemented for Phase 9.5v
- Date: 2026-09-10

## Context

The transparency ledger needs live publications, but an agent cannot safely
create a key until it knows the stable cluster identity, immutable Node UID,
current topology revision, and exact peer frontier. Node names and controller
process epochs are not sufficient identities.

## Decision

Phase 9.5v introduces **Durable Edge-Key Bootstrap**.

The controller derives the encryption cluster identity from the Kubernetes
`kube-system` Namespace UID. Its internal TLS API returns a digest-bound
bootstrap only to the current TokenReview-authenticated agent Pod. The bootstrap
contains the controller incarnation, stable cluster ID, topology revision,
exact recipient, and complete member list.

The agent creates a dedicated real mode-0700 directory and a mode-0600 key
checkpoint. It restores only an exact cluster/name/Node-UID authority or creates
one with OS-CSPRNG material, then durably prepares the first epoch against every
other member UID before publishing. Only `NodeKeyPublication` crosses the API;
private bytes remain behind the Node-local store and kernel boundary.

The controller authenticates the publication again, refreshes the complete-cut
ledger membership, and accepts it only at the bootstrap topology revision.

## Consequences

- Cluster identity survives controller restart without manual configuration.
- Node-name reuse cannot recover or publish an old private authority.
- Persistence failure prevents public-key publication.
- Multi-Node initial epochs remain Prepared until mutual acknowledgements land;
  a key publication alone cannot produce an active plan.
- Offline development uses an explicit non-production identity and cannot be
  confused with connected Kubernetes identity.

## Verification

`make encryption-key-runtime-test` inherits the transparency gate, exercises
stable bootstrap, Node/UID authentication, complete-cut ingestion, CSPRNG epoch
creation, exact restart recovery, directory/file modes, and replacement denial,
then applies strict Clippy across encryption, controller, and agent.
