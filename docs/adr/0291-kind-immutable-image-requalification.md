# ADR 0291: Kind Immutable-Image Requalification

Date: 2026-09-13

Status: isolated environment and identity assertions prepared; full Kind pending

## Context and decision

ADR 0290's strict cl02 gate passed before creating this fresh three-Node,
dual-stack, default-CNI-disabled and kube-proxy-free Kind environment. The
runtime remains `cb59e90`; no Rust binary or encryption authority changes.

Registry downloads were slow and the ordinary Btrfs container store has metadata
pressure. Use a separate rootful overlay store under a private `/tmp` directory,
with separate runtime/network paths. Do not prune or reset the user's store.
The temporary inotify instance increase from 128 to 1024 must be restored after
removing this qualification cluster. This tmpfs-backed environment is not a
production memory-efficiency benchmark.

Export the locally built controller, agent and test tools as gzip OCI archives.
Their manifests reproduce the exact immutable Quay digests from cl02:

| Component | SHA-256 manifest |
|---|---|
| Controller | `bebf58850e8bd17d8e273f1de1ad49c4f8d3aacb2cf969e623bf66d77d602ed0` |
| Agent | `b2b7c200b50845f08c554fb4274bcf4d8fd645ce39dadae282a621da10541494` |
| Test tools | `e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352` |

Validate archive manifest/config hashes and imported containerd targets before
using fully qualified references. The rollback helper's `localhost/unf-agent:dev`
alias is explicitly bound to the same imported agent manifest, not rebuilt.
Owner-only kubeconfig and TLS keys remain ignored; no credentials enter Git.

The cached Kubernetes 1.35.0 node image is repackaged without changing its config
or root filesystem. Original index `452d707d…ac31f` contains amd64 manifest
`b7f5e1f6…3629b`. The local uncompressed manifest is
`27b63b182c80a24703b0e7e8ced76b01a7c4f0339e28da8f53a0a7f7445d0efc`;
the unchanged config is
`17b4349087ddad8a3d8b0353c6ae032ce336cd2161d26a989c8bee9fc43c2139`.
Config, RootFS diff-ID list, command, entrypoint and labels compare equal against
the original cached image. The private Kind configuration pins the new digest;
it does not mislabel that repackaging as the original registry manifest.

## Preparation findings

The first containerd transfer import produced short archive tags. CRI normalized
them to a different name, failing container creation before UNF execution.
Fully qualified references and a restart of only the new Kind nodes' containerd
cleared the stale import cache. No cl02 runtime was changed.

Agents initially exited twice because the controller TLS/node-block endpoint
was not yet available and there was no last-known-good snapshot. Once the
controller started they recovered. Preserve initial logs and Pod states; the
normal post-bootstrap agent rollout establishes a new qualification baseline,
not a claim of crash-free initial installation. Startup retry/backoff remains
stabilization work.

Live Kind containerd returns `repository@sha256` image IDs. The old gate accepted
only bare IDs. Accept a complete bare SHA-256 (with the independent build-version
check), or a fully qualified immutable ID exactly equal to the requested image.
Reject malformed IDs, mismatched repositories/digests and trailing newlines.
`verify-phase9-runtime-image-id.sh` tests both forms under jq 1.6 and 1.8.1; the
predicate validates the captured cl02 observations and live Kind PodSpec/status
join. Kind's controller now uses the same requests (100m/256Mi) and limits
(2 CPUs/2GiB) as the already-qualified cl02 controller; these are safety ceilings,
not measured optimal budgets. The post-bootstrap runtime has four Ready Pods
with zero restarts.

## Remaining gate

Run the complete committed Kind qualification with exact runtime revision and
test-tools digest, including ciphertext/outage, rotation/replacements, bounded
history, egress coexistence, cleanup and no-CNI rollback. Keep Phase 9 In progress
until that run passes. S1–S5 resource/load qualification remains separate.
