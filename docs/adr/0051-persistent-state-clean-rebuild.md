# ADR 0051: Persistent-state ABI changes use a converged clean rebuild

Status: Accepted and live verified on dual-stack Kind

## Context

The compatibility tuple treats a persistent BPF-state ABI change as an explicit
boundary. ADR 0050 proves that an incompatible agent cannot accidentally adopt
the prior ABI directory, but rejection alone does not provide an operational
transition. A safe transition must not attach an empty policy map set, retire
the last-known-good attachment too early, or leave an unrecoverable partial
state after failure.

The current map representation does not justify a byte-level transformer.
Identity and policy snapshots are the controller's authoritative desired state,
so rebuilding a new ABI directory from those snapshots is simpler and safer
than translating kernel map bytes.

## Decision

Persistent-state ABI changes use a deliberate clean-rebuild contract:

1. A complete, validated pinned map set may still attach and restore service
   without the controller.
2. A fresh or incomplete ABI directory must successfully receive and commit
   both identity and policy snapshots before any TC program is attached. A
   missing or failed controller synchronization stops startup while the new
   state remains unattached and safe to retry.
3. The controller is upgraded first while wire schemas remain compatible.
4. Agents move to the new versioned pin directory one node at a time. The old
   attachment and maps remain active until the replacement has populated its
   maps, attached, reported Ready, and converged.
5. Old ABI pins and TCX links are removed only after every expected node has
   converged on the new ABI. Cleanup remains dry-run-first, refuses unknown
   content, and accepts only ABI versions known to the executing binary.
6. Rollback repeats the same process in reverse: rebuild the older ABI from
   controller snapshots, attach node-serially, verify full convergence, then
   use a binary that recognizes the newer ABI for scoped cleanup.

This is an operational state rebuild, not a byte migration, dual-read/write
map format, or general compatibility claim between arbitrary ABIs. The test-only
v4 derivative changes only the persistent-state ABI constant; every wire schema
and eBPF map layout remains fixed so the gate isolates lifecycle ordering.

## Qualification gate

`make kind-clean-rebuild-test` accepts only a clean committed worktree. It
archives that exact revision and derives controller and agent fixtures with
persistent ABI 3 changed to 4. The images carry source-revision and ABI-boundary
labels and remain local test artifacts.

On two-node dual-stack Kind, the gate:

- verifies the current v3 controller, two v3 agents, all eleven maps, populated
  identity/policy state, and pinned TCX links;
- keeps TCP/8080 allowed and TCP/9090 denied continuously;
- upgrades the v4 controller while both v3 agents remain converged;
- replaces one agent at a time and requires the explicit pre-attachment
  population log, populated status, and simultaneous v3/v4 pin sets;
- removes v3 only after both v4 agents converge;
- performs the reverse fresh rebuild to v3 one node at a time; and
- runs an exact-node, privileged, host-bpffs cleanup Pod from the v4 agent image
  to remove only v4 after v3 convergence, then restores the normal deployment.

The failure trap restores the current controller and v3 DaemonSet before making
a best-effort exact v4 cleanup. It never recursively removes the UNF root.

## Evidence

On 2026-08-27, the complete gate passed on its first attempt from implementation
revision `e39ac5cfbbe6f9fa7218bc4ed9693b5d653c80b4`.

The current local images were controller
`baa44b20d00817d86448007816609f2f1ca1b9b3e34c0d7c782fa92a7b93a4c8`
and agent
`4b1589594615fd9ec26c5d4a12798060e8542d4c36f7651686f227b6753b57e5`.
The derived labeled v4 images were controller
`2a4aaaf8dd24399789137dc79459e3891170a01f6b6f6f63a57c1fdacc407f64`
and agent
`2d03bcdb29f1e6214692f86dc1d4fea2b656ec285437ad9fdee421b93dd5aa63`.

Both Kubernetes 1.35.0 nodes used the Linux 7.1.4 TCX fixture. Every forward and
reverse node transition became Ready with nonzero identity and policy entries,
the expected eleven-map ABI directory and TCX links were present, old state was
absent after scoped retirement, authenticated controller convergence returned
to two of two agents, and the continuous probe recorded no outage or breach.
The final deployment ran the current v3 controller and two current v3 agents;
v4 state was absent on both nodes.

Before the live gate, formatting, strict workspace lint, all 168 workspace tests,
shell syntax, and diff checks passed. The target also rebuilt the release eBPF
object and both current and derived release images from the committed revision.

## Consequences

UNF now has a repeatable, failure-safe clean-rebuild path for a persistent ABI
boundary when controller wire schemas remain compatible. Fresh state cannot
briefly attach as allow-all/empty policy state, and retirement authority is
delayed until cluster convergence.

This does not qualify a real map-layout translator, a simultaneous wire-schema
change, unsupported direct downgrade, OpenShift legacy-netlink migration, or an
arbitrary multi-version span. Unsupported downgrade classification and rollback
reporting remain milestones 2.4 and 2.5; OpenShift qualification remains
milestone 3.
