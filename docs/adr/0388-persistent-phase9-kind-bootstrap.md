# ADR 0388: Separate Persistent Phase 9 Kind Bootstrap

Date: 2026-09-21

Status: infrastructure bootstrap verified; Phase 9 qualification unchanged

The user approved a separate fresh dual-stack Kind environment after the old
temporary runtime disappeared following a workstation reboot. Historical
evidence and the default Podman stores/containers are preserved. This creates
new Node identities, not retained-state continuity with the old cluster.

`unf-p9-20260921` uses Kind v0.32.0, the repository's pinned v1.35.0 three-Node
service-fabric configuration, no default CNI and no kube-proxy. Its dedicated
rootful Podman graph root and `/var` volumes are under
`/var/lib/unf-kind/phase9-20260921/storage`, not `/tmp`. Runtime-only state is
under `/run/unf-kind-phase9-20260921`. The isolated dual-stack network is
`unf-p9-20260921`, bridge `unfp9br0`, subnets `10.90.91.0/24` and `fd90:91::/64`.
Kind's network override is explicitly experimental/unsupported; this is a lab
configuration, not a production support claim. Host kernel is now
`7.2.5-200.fc44.x86_64`, so historical kernel qualification is not inherited.

Bootstrap uses the last cl02-passing runtime from ADR 0386,
`f984db9e8b041c014814958054a1908e9829233c`, with the **Native** baseline:

- Controller: `quay.io/arencloud/unf-controller-dev@sha256:27ca5f02cc76a6c3f5694d5e730f1b0b2399f7954b5c41f277c94061a59e6c5e`.
- Agent/installer: `quay.io/arencloud/unf-agent-dev@sha256:4062add8cd5ead92cdd7decc293de44851eaab1d012fc075802d41ffe8065eb7`.
- Installed CNI SHA-256: `09129e9c91cc3434b0253bf7d4c811870f2e6e72ce6bf3e4b88eba7b03a4cd47` on all three Nodes.

Public image pulls succeed without registry credentials. TLS keys and the new
kubeconfig remain permission-restricted and ignored by Git. All Nodes are Ready;
the controller and all agents report the exact revision, agents report loaded
BPF and ABI 15/encryption ABI 2, and all three controller reports are fresh and
converged. No container restarted. All seven regular/init log streams were
reviewed: 2,005,477 bytes, no WARN/ERROR, no observer failures. This short
bootstrap window is not a load/soak test; its substantial INFO log volume still
needs stabilization measurement.

The read-only check is `hack/verify-phase9-persistent-kind.sh`. Its first attempt
used the wrong installed CNI filename (`unf-cni` rather than `unf`) and failed;
the corrected complete run passes. Evidence is retained separately:

- `.artifacts/p9-kind-persistent-20260921`: creation and rendered bootstrap.
- `.artifacts/p9-kind-persistent-20260921-check-v2`: passing complete checks.
- `.artifacts/p9-kind-persistent-20260921-final-logs`: reviewed logs.
- Node inventory SHA-256: `ee5db05bf134a1832eb9144eb2594f6998a082eff5ee94f6295cc0f047daab0d`.
- Controller convergence SHA-256: `432d70dbc035216d0f3248b8cf2f675cc53844461addb21fd3b3ac3e38041064`.

Node UIDs:

| Node suffix | UID |
|---|---|
| control-plane | `fb38e91d-c6a1-47a9-a0e7-2719ac3657b4` |
| worker | `bab6dc45-3f5d-4cc1-8c7f-d3c66af25b5f` |
| worker2 | `bac15646-99b6-4523-a07c-3b20e184dab7` |

No host reboot, automatic-start or post-reboot recovery test is claimed. See the
[operating runbook](../development/phase9-persistent-kind.md). cl02 still runs
`d007071`; ADR 0387's failed Required gate remains unqualified. Repair and pass
cl02 before advancing the new Kind runtime. L3/L4/L5/Q, Phase 9.8/9.9 and S1–S5
remain open. No release pins change.

## Parallel read-only cl02 recovery checkpoint

The morning observation finds all five agents at Native active generation
`1789972093114`, with no pending recovery plan and empty active/pending/retiring
transport lists. Ordinary policy/Service reports are fresh and converged at
443 / 202. Thus ADR 0387's pending Native cleanup eventually clears without our
resetting any authority; the time to recovery was not continuously observed.
This is not a rerun or repair of the failed Required gate.

All eleven current controller/agent/installer streams were reviewed over the
bounded 20-minute window. There are no ERROR entries, but 419 bounded-flow-history
warnings, sixteen active path-proof retries, eight topology-history warnings,
and one each key-publication, Service-sync and clsact warning. Agent configuration
is `RUST_LOG=unf_agent=warn`, so successful INFO-level key lifecycle events are
absent from both this window and the failed run. No exact epoch-retirement
timeline can be inferred from their absence.

Source review identifies a further lead: the controller's unactivated-catalog
reuse barrier checks contract wall-clock validity, not current local key
availability. It must be examined alongside transport-free retirement and
pending-generation ownership. This is not a demonstrated sole cause and no
guard has been removed. Next implementation needs a deterministic regression
and exact key/plan/generation evidence without exposing private keys, followed
by complete cl02 qualification before new Kind qualification.

Evidence: `.artifacts/p9-cl02-resume-20260921` and
`.artifacts/p9-cl02-resume-20260921-logs`. Recovery summary SHA-256:
`2143482b8b96ee89dde32605b091bdb443dac374d27e81add6646bd2e7df723e`.
