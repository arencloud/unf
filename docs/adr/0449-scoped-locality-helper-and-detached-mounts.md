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
It returns only the root directory FD, never a namespace/configuration FD. No
mount tree is cloned or modified, no shared pin pathname exists, and no temporary
mount directory needs cleanup. The agent uses its own BPF capability through
`/proc/self/fd/<held-directory>`; final directory-reference closure releases the
filesystem while independently held map/program FDs can survive. The root is
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
| Detached-mount protocol and ownership | Implemented; local tests, then immutable cl02-first/Kind kernel gate |
| Production supervisor and endpoint authentication | Pending: private socket delivery, process/Pod identity, single persistent worker slot, bounded cancellation and child reaping; no UID-only public service |
| Descriptor-bound namespace observations | Pending: link/route/cookie readbacks and fresh recheck, no caller pathname lookup or policy authority |
| Restricted device seeding | Pending: exact program/map provenance, fixed non-transmitting operation, no general BPF execution API |
| Loader/publisher integration and recovery | Pending: use helper without adding SYS_ADMIN to agent; process crash/disconnect/replay, foreign-state preservation and all existing publication fences |
| Platform deployment | Pending: reviewed separate helper SCC/seccomp/SELinux and agent's original three-capability profile; cl02 before matching Kind |

Do not migrate production journals, promote L3/L4/L5/Q or claim Phase 9 Verified
from the first boundary. Helper failure must keep the consuming path withdrawn;
there is no direct-privilege or shared-pin fallback. IPC belongs only to bounded
control-plane preparation, never the per-packet path. S1–S5 measurements remain
separate, including peak preparation memory, cancellation latency and load cost.
