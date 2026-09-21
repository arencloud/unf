# ADR 0445: Locality fleet privilege preflight

Date: 2026-09-21

Status: fleet rollout held pending an explicit privilege-boundary decision

Read-only preflight finds that cl02's actual `unf-agent` container is root but
not privileged. It drops all capabilities and adds only BPF, NET_ADMIN and
PERFMON. Its effective/permitted/bounding mask is `000000c000001000`,
NoNewPrivs is 1, and seccomp filtering is enabled. The `unf-primary-agent` SCC
also lists only those three added capabilities. The existing installer sidecar
is separately privileged. Persistent Kind's agent is privileged already.

The new consumer performs namespace-bound device observation/seeding, and
ADR 0443 adds a private mount namespace for crash-safe loader pins. Linux
requires SYS_ADMIN for network-namespace entry and creation of a mount
namespace: see the primary [setns(2) documentation](https://man7.org/linux/man-pages/man2/setns.2.html)
and [unshare(2) documentation](https://man7.org/linux/man-pages/man2/unshare.2.html).
NET_ADMIN alone is insufficient. Removing the private-mount change would not
solve the already-required namespace observation/seeding boundary.

Privileged disposable diagnostics therefore cannot establish deployability
under the current restricted cl02 agent configuration. Do not promote fleet
support or begin an irreversible schema-5 journal migration on that evidence.
No SCC, capability, production image, map or journal has been changed.

The user has been asked to choose:

- Implement a narrowly scoped privileged helper first, retaining the agent's
  current capability boundary. This needs a reviewed authenticated/FD-bound
  helper protocol and additional isolation/failure/lifecycle qualification.
- Explicitly permit SYS_ADMIN for the cl02 lab agent, keeping privileged=false
  and the existing SELinux settings, then qualify that exact SCC/seccomp/runtime
  configuration before fleet admission. This is a meaningful privilege expansion,
  not an equivalent least-privilege profile or a production recommendation.

The prepared, ignored rollout helper has an explicit approval hold and checks
both the desired capability and SCC before any rollout. It is not executed.
Runtime images are being prepared separately; image publication is not rollout
or platform qualification. Finish already-running disposable gates, but do not
infer authorization to expand cluster privileges from the Phase 9 objective.

Read-only evidence root:
`.artifacts/p9-locality-runtime-762c980-cl02-capability-preflight`.

| Artifact | SHA-256 |
| --- | --- |
| DaemonSet | `f57644ba9eae1ae647a6149e01c427e1be091c8860a5fed6916df93771c4b3f0` |
| SCC | `2f36bca80b0956e93c389db126c768b42bb76b3f0ebb20768de9546de8962c8b` |
| Effective capabilities | `509fe9b3d7ec1c617c350e4f10b83c966dfb8da01e76deb5f0abc44f13d9ba56` |

Phase 9 remains open. Full agent recovery, authenticated fleet reconciliation,
workload replacement, mixed replicas, remote Required/current-runtime lifecycle
and consuming status still require completion. S1–S5 remain separate.
