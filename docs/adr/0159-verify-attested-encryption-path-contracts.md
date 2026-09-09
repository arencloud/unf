# ADR 0159: Verify attested encryption path contracts

**Status:** Accepted and implemented for Phase 9.2

## Context

ADR 0158 requires identity-level encryption authority without a tunnel per
workload or policy. Before key generation, kernel WireGuard configuration, or
packet steering can begin, UNF needs a Kubernetes-independent answer to three
questions: which identity pairs require encryption, which exact two-Node path
facts authorize later staging, and whether another component can independently
reproduce that decision.

An optional-encryption rule that overrides a required baseline would introduce
a downgrade path. A contract containing only a peer endpoint and key would lose
the policy, workload, route, and reverse-path facts that distinguish configured
WireGuard from an authorized workload path. Accepting overlapping `AllowedIPs`
for different active destination Nodes would also make peer ownership
ambiguous.

## Decision

The new `unf-encryption` crate owns two schema-v1 Kubernetes-independent types:

1. `EncryptionModel` contains one cluster identity, a `Native` or `Required`
   baseline, and bounded selective source/destination identity intents.
   Selective intents can only add Required encryption. Matching intent UIDs are
   retained canonically as provenance; no rule can weaken a Required baseline.
2. `AttestedEncryptionPathContract` is issued for one exact source Node from a
   complete set of endpoint, source-policy, public-key epoch, and bidirectional
   desired-route facts. It carries no private-key field and changes no host or
   packet state.

Contract compilation first canonicalizes and validates the whole model and fact
set. Node names and UIDs are one-to-one, workload endpoints are exact, public
keys are nonzero and unique for an epoch, key validity covers the contract
lifetime, every required Node exposes the complete bounded capability set, and
cross-cluster facts are rejected in Phase 9. Source policy is resolved before
keys or paths: denial emits no encryption plan, while an allowed Required pair
must carry nonempty exact policy IDs.

Every plan binds the source/destination identities, workload UIDs, cluster and
Node identities, all matching encryption intents, sorted policy IDs, both
public keys and their domain-separated digests, one common epoch, exact forward
and reverse endpoints, canonical Pod CIDR `AllowedIPs`, interface name, route
table, fwmark, MTU, contract lifetime, and five independent revisions. Each
direction must target an authoritative underlay address of the remote Node and
its `AllowedIPs` must equal that Node's exact Pod CIDRs. Nested prefixes on one
Node and overlapping active prefixes across different destination Nodes are
rejected.

The contract digest uses the domain
`unf.attested-encryption-path-contract.v1`. A 128-bit decision witness uses a
separate domain and binds the complete digest plus exact identity/Node/epoch/
route/revision selection. It is provenance, never authority. Independent
verification recompiles from the original model and facts and compares the
entire result; integrity-only verification is reserved for rejecting corrupt
durable bytes.

The bounded failure envelope enumerates source-key, destination-key, forward-
path, reverse-path, and future mutual-evidence loss for each Required plan. Every
outcome is explicitly `DenyRequired`; total count and truncation remain visible.

## Evidence

`make encryption-contract-test` runs the Phase 9 architecture drift gate,
contract-specific static assertions, eleven domain tests, one property test,
and strict all-target/all-feature Clippy. The tests cover:

- monotonic Required baseline and selective intent semantics;
- policy-first denial and missing authority;
- canonical input permutation with frozen schema-v1 digest and witness bytes;
- full independent replay and mutation of policy, key epoch, route, revision,
  and failure evidence;
- key lifetime, Node capability, Node name/UID, public-key uniqueness,
  cross-cluster, nested-prefix, and cross-Node `AllowedIPs` rejection; and
- strict unknown-field deserialization with no private-key-shaped contract
  field.

## Consequences

- Milestone 9.2 is a model/reference-verifier result. It creates no CRD, key,
  interface, peer, route, fwmark, BPF ABI, packet behavior, or platform claim.
- Identity selectors are already-resolved domain inputs. Kubernetes label,
  Namespace, ServiceAccount, and compatibility conversion remains a later
  controller-adapter boundary and cannot enter the core contract.
- `Native` exists for pre-qualification and staged-upgrade models. A Required
  decision has only a denial failure outcome; plaintext fallback is
  unrepresentable in the contract.
- Current Phase 9 rejects overlapping active Node CIDRs. Cross-cluster virtual
  identity and overlapping-CIDR translation remain Phase 10+ work and must use
  a new explicit path class rather than weakening this invariant.
- Key facts are public desired-state inputs only. Node-local private-key
  generation, zeroization, persistence, publication, and two-epoch rotation
  begin in milestone 9.3.
