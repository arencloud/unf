# ADR 0449: Scoped locality helper and detached BPF-filesystem handles

## Decision and supersession

The operator now selects the recommended scoped helper, superseding the lab
SYS_ADMIN expansion in ADR 0448. Do not apply those historical patches or deploy
the prepared capability-expanded fleet. The actual agent/SCC remain unchanged.
The diagnostic attempt recorded under `p9-lab-profile-6b32980-cl02-main` failed
before kernel tests because selinuxfs was hidden in the container. Its exact
capabilities, NoNewPrivs, seccomp and `spc_t` observations are retained; it is
not qualification. Independently observed host SELinux was Enforcing.

The objective is a smaller privilege boundary, not an unsupported novelty or
performance claim. The agent retains placement/journal validation, policy and
publication authority. The helper must offer specific bounded operations, not
arbitrary exec, namespace paths, mount options or unvalidated BPF execution.

## First implemented boundary

`unf_locality::helper` supplies a single-use Unix SEQPACKET exchange with exact
kernel peer credentials and per-message credentials, a fixed 40-byte versioned
operation, random 32-byte response binding, five-second send/receive timeouts,
CLOEXEC descriptor receipt and rejection of unknown/excess/truncated ancillary
data. Rejected descriptors close on every path. No client descriptor is accepted
by the mount operation. There is no public listener or implicit fallback.

The helper creates a **detached bpffs** through `fsopen`, `fsconfig` and `fsmount`.
It returns only a private adapter-directory FD, never a namespace/configuration FD. No
mount tree is cloned or modified, no shared pin pathname exists, and no temporary
mount directory needs cleanup. The agent uses its own BPF capability through
`/proc/self/fd/<held-directory>`; final directory-reference closure releases the
filesystem while independently held map/program FDs can survive. The directory is
checked as root-owned, private, empty bpffs. No policy/packet permission follows.

The underlying primitives already exist in Linux; see the primary Linux 5.14
[bpffs implementation](https://github.com/torvalds/linux/blob/v5.14/kernel/bpf/inode.c)
and [mount implementation](https://github.com/torvalds/linux/blob/v5.14/fs/namespace.c).
Compatibility and security still require actual RHCOS/SELinux/seccomp tests.
This is a proposed simplification of UNF's loading path, not a benchmark result.

## Verification and remaining integration

Local negative tests cover socket/credential checks, fixed framing, disconnect,
stale replies, wrong descriptor types, inbound descriptors, ancillary truncation,
positive descriptor closure and deadlines. Strict Clippy is required.

The isolated kernel gate binds its compiled revision and tests helper effective/
permitted capabilities restricted to SYS_ADMIN, client capabilities restricted
to BPF/NET_ADMIN/PERFMON, client namespace creation denied, actual BPF pinning,
map-FD survival, pin reclamation and unchanged parent mount namespace. These
are joined test threads with real kernel credential checks and SCM_RIGHTS, not
yet separate production containers or full process-crash qualification.

| Slice | State / closure requirement |
| --- | --- |
| Detached-mount protocol and ownership | **Verified isolated boundary**: source `c929d55` passes cl02 then identical Kind; 921 workspace tests pass. ADR 0450 records limits and complete evidence; this is not production-process integration |
| Production supervisor and endpoint authentication | ADR 0451 implements sealed-executable owned-child supervision, credential-bound rendezvous, pidfd cancellation and a retained single slot; isolated cl02/Kind process gates pending. Production Pod/bootstrap delivery and parent-death/crash matrix remain separate; no UID-only public service |
| Descriptor-bound namespace observations | Pending: link/route/cookie readbacks and fresh recheck, no caller pathname lookup or policy authority |
| Restricted device seeding | Pending: exact program/map provenance, fixed non-transmitting operation, no general BPF execution API |
| Loader/publisher integration and recovery | Pending: use helper without adding SYS_ADMIN to agent; process crash/disconnect/replay, foreign-state preservation and all existing publication fences |
| Platform deployment | Pending: reviewed separate helper SCC/seccomp/SELinux and agent's original three-capability profile; cl02 before matching Kind |

Do not migrate production journals, promote L3/L4/L5/Q or claim Phase 9 Verified
from the first boundary. Helper failure must keep the consuming path withdrawn;
there is no direct-privilege or shared-pin fallback. IPC belongs only to bounded
control-plane preparation, never the per-packet path. S1–S5 measurements remain
separate, including peak preparation memory, cancellation latency and load cost.

## First platform attempt

Source `f4c257e`, image
`quay.io/arencloud/unf-test-tools-dev@sha256:87a520365345712989a8cdd651e1b249abd715f6847b01593bd99274b9e40369`,
passes the cl02 kernel gate. The identical Kind attempt fails with a closed
helper channel; the fixture's early client unwrap masked the helper error.
Both diagnostic Namespaces were removed. All five cl02 journals are byte-exact,
all production Pods retained zero restarts, and complete current/retained logs
show no ERROR or partial/non-JSON observations. Existing warnings remain:
425 flow-history retention, seven peer-proof, four topology-retention and one
key-publication warning in the final current window; 13,831 retained WARNs in
23 categories. Kind and the paired milestone are NOT Verified.

The fixture now always joins/reports helper failure before unwrapping the client,
and filesystem syscalls retain operation context. Preserve the original evidence
under `.artifacts/p9-helper-mount-f4c257e-{cl02,kind}-gate`; do not attribute the
Kind cause before the improved observation has run cl02 first and then Kind.

Source `de05a3c` again passes cl02 and identifies Kind's concrete rejection:
`helper mount is not empty: "progs.debug"`. Its fresh bpffs contains kernel
preload entries. The helper now creates one exclusive mode-0700 adapter
subdirectory in its detached filesystem and passes that FD; it does not delete
or ignore entries in the adapter directory, reuse EEXIST, or modify kernel
preloads. A regression preserves both preload-like entries and existing adapter
residue. Requalify this source on cl02 before identical Kind; earlier failures
remain retained and are not relabeled as passes.
