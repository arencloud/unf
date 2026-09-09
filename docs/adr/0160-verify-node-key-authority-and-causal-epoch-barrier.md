# ADR 0160: Verify Node key authority and the Causal Epoch Barrier

**Status:** Accepted and implemented for Phase 9.3

## Context

Phase 9.2 accepts only public key facts, but a real encryption fabric also needs
an authority that creates and retains the corresponding private keys. Putting a
private key in a Kubernetes Secret would make the control plane and every
credentialed backup path part of the Node transport trust boundary. Replacing a
Node by name could also accidentally transfer an old key identity to new
hardware.

A cluster-wide rotation barrier is safe but unnecessarily couples unrelated
Nodes and performs poorly at scale. Conversely, majority/quorum activation can
leave an affected peer unable to decrypt Required traffic. UNF needs a barrier
whose scope is small enough to scale and exact enough to prevent partial
activation.

## Decision

`unf-encryption` now owns a Node-local, deliberately non-serializable
`NodeKeyAuthority`. `OsWireGuardKeyGenerator` fills 32 secret bytes from the OS
CSPRNG through `getrandom`, derives the corresponding public key with the
maintained `x25519-dalek` X25519 implementation, and wraps every userspace
secret buffer in `zeroize::Zeroizing`. UNF still implements no cipher, key
agreement protocol, or packet cryptography; the kernel WireGuard provider will
consume the key in milestone 9.4.

Only the private Node-local checkpoint format can serialize secret material.
The store requires an absolute, symlink-free mode-0700 directory and a regular,
single-link, same-owner mode-0600 file. It writes a new temporary file, syncs
it, atomically renames it, syncs the parent directory, and revalidates the final
path. A domain-separated digest detects corruption. Restore additionally
re-derives every public key and requires the exact cluster, Node name, and Node
UID. Temporary serialization buffers and discarded transaction candidates are
zeroized.

Every state transition is copy-persist-commit. A failed write cannot advance
the live authority, while a crash after durable rename recovers the newer
state. At most two live secret epochs are representable. The lifecycle is:

`Prepared -> MutuallyAttested -> Active -> Draining -> Retired`.

Retired keys are removed rather than retained as secret-bearing history. A
monotonic retired floor proves non-reuse. Emergency revocation first removes
and zeroizes all affected live epochs, advances a monotonic revoked floor, and
emits a public digest-bound receipt; Required flows therefore lose key
authority before later route cleanup and cannot fall back to plaintext.

### Causal Epoch Barrier

Preparation seals the target Node UID, new epoch/public-key digest, exact
topology revision, expiry, and the bounded set of affected peer Node UIDs into
one domain-separated Causal Epoch Barrier. That peer frontier is derived from
actual required encrypted relationships, not every Node in the cluster. Each
acknowledgement must arrive over the existing authenticated Node-UID boundary,
refer to the exact barrier, and include the acknowledging peer's nonzero public
epoch. Exact replay is idempotent; mutation, an unlisted identity, expiry, or
topology drift denies activation.

Activation needs every peer in that exact frontier—there is no unsafe majority
shortcut. This creates a useful scale/safety property: unrelated Nodes do not
delay a rotation, while every Node whose traffic could be affected must be
ready. The resulting readiness certificate is reproducible from the complete
canonical acknowledgement set.

New activation makes the prior epoch `Draining`. Its secret remains available
for already admitted flows only, within a bounded deadline. Retirement requires
a digest-bound positive local proof of zero established flows and zero owned
routes; time passage alone is not proof of cleanup.

Public `NodeKeyPublication` contains only Node identity, monotonic revision and
epoch floors, public keys, phases, bounded counts, barrier/readiness digests,
and deadlines. Admission binds it to an authenticated cluster/Node name/Node
UID, accepts exact idempotence, rejects same-revision mutation and revision
replay, prevents public-key or phase regression, and requires explicit fencing
before a replacement Node UID may reuse a Node name.

## Evidence

`make encryption-key-authority-test` runs the Phase 9.1 and 9.2 prerequisites,
static boundary checks, all key-authority tests, and strict all-target/
all-feature Clippy. Tests cover:

- two distinct OS-generated nonzero keys and redacted debug formatting;
- complete exact-frontier readiness, idempotence, forged identity, mutation,
  expiry, and topology-revision rejection;
- initial activation, two-epoch rollover, positive zero-flow/zero-route drain,
  retirement, capacity, and lifetime bounds;
- emergency revocation, monotonic non-reuse, and receipt integrity;
- authenticated public-only publication, replay/regression/mutation rejection,
  and replacement-UID fencing;
- atomic durability failure without in-memory advancement; and
- owner-only restart recovery plus symlink/hardlink, checkpoint mutation,
  private/public mismatch, and Node UID reuse rejection.

The key derivation and memory-clearing dependencies require Rust 1.85 or newer,
below UNF's Rust 1.89 workspace floor. Their upstream contracts are documented
by the [WireGuard protocol](https://www.wireguard.com/protocol/),
[`x25519-dalek` `StaticSecret`](https://docs.rs/x25519-dalek/3.0.0/x25519_dalek/struct.StaticSecret.html),
[`getrandom::fill`](https://docs.rs/getrandom/0.4.3/getrandom/fn.fill.html), and
[`zeroize`](https://docs.rs/zeroize/1.9.0/zeroize/).

## Consequences

- Private keys now exist only in transient zeroizing memory and the exact
  owner-only Node-local checkpoint. No controller API, Kubernetes object,
  publication, log, metric, evidence object, or controller checkpoint gains a
  secret field.
- The public-key publication is authenticated by the existing workload/Node UID
  transport boundary; X25519 public keys are not repurposed as signing keys.
- The exact affected-peer frontier provides bounded work proportional to active
  encrypted relationships, but a required peer that is genuinely unavailable
  intentionally blocks that affected rotation.
- Hardware-backed keys/TPM attestation, post-quantum algorithms, cross-cluster
  trust, and encrypted backup of local keys remain explicit exclusions.
- This milestone does not create a WireGuard interface, program a kernel key,
  alter routes/BPF, or move packets. Transactional kernel provider integration
  begins in milestone 9.4.
