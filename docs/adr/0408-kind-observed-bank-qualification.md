# ADR 0408: Matching Kind Observed Locality Bank Qualification

Date: 2026-09-21

Status: complete disposable observed-bank fixture verified on cl02 then Kind

After ADR 0407, the identical `b9a824a` diagnostic image
`quay.io/arencloud/unf-test-tools-dev@sha256:6ce5d918c67fc5132065a94561d55112556fde5f04a95b96bc89d71cdd27ef0e`
passes on persistent Kind Node `unf-p9-20260921-worker`, UID
`bab6dc45-3f5d-4cc1-8c7f-d3c66af25b5f`, on kernel 7.2.5. The actual container
image ID agrees; exit code and restart count are both zero.

All 28 native observation cases pass, followed by the same two-endpoint,
four-address real-journal/kernel bank fixture as cl02. Independent UDP/netlink
namespace-cookie parity, full ownership aliases, retained descriptors, route
drift/cancellation retirement, stale-context/cut rejection and scoped kernel
lease revocation pass. All fixture links/routes/namespaces and the owned
Kubernetes Namespace are cleaned up. No workload packet delivery is tested.

The two existing worker CNI journals remain byte-identical. The control-plane
journal remains absent, with an independent API check confirming no non-host
workload requires one; absence is not synthesized as an empty journal. All
three current agents converge at policy 47 / Service 19. Runtime Pods remain
Ready with zero restarts, and their `6d71a30` images are unchanged.

All current regular/init logs and retained agent CRI logs are reviewed. The
final current window has four proof-assistance warnings. Retained logs contain
79 warnings, including prior recovery: 42 plan synchronization, 22 proof
assistance, four incomplete activation and eleven single-occurrence categories.
No ERROR, failed log observer or truncated read is present. Historical failures
remain evidence; this pass does not waive ADR 0407's separate cl02 encryption
key-floor/witness finding or qualify sustained-load behavior.

Evidence: `.artifacts/p9-observed-bank-b9a824a-kind`, with before/during/after
logs, journals, retained CRI and controller snapshots under
`.artifacts/p9-observed-bank-kind-*`. Evidence JSON SHA-256:
`03137d663ad630a4260adde146e19236240e8e3fe94859f9cee683a4fcb2a69b`.
Timestamped test log SHA-256:
`65d3d6ab57273a5ada851d8158d4f01525b085d7824c75710cda513500d992bb`.

Observed-bank preparation is now qualified on both deployed kernels. Production
device maps/program publication, agent/packet consumption, migration and full
L3/L4/L5/Q remain open. No release pin, admission claim or Phase 9 status is
promoted by this prerequisite alone.
