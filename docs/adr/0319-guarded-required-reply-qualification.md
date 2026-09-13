# ADR 0319: Guarded Required Reply Qualification

Date: 2026-09-13

Status: candidate published and gate implemented; live results pending

## Candidate

Runtime `67c27727d92e86332298724e399b9b6e63f0c6af` implements ADR 0318.
Both isolated controller/agent version APIs report that exact committed source
revision. Images are published only to the development repositories and their
manifest digests are independently checked through anonymous pulls:

| Component | Manifest SHA-256 |
|---|---|
| controller | `20595c29f183d5132b63ff4185a4905d10e7717a6669ecd6ef76aef9b376e1af` |
| agent | `9bd8a58d8cc531a05f02231dd879cb264edd78a4731c29360595d7fa1dabd7d7` |

Each contains the unchanged RHCOS-verified eBPF object
`d8551daad5f6222a8b9ddd7b3e7ed5d869bdea53c99b1e8c692f8ec0c205a27d`.
Release pins are updated, but full Kind qualification remains pending. Serial
cl02 deployment keeps the existing Native baseline and ADR 0315's candidate
health guard. It must preserve journals, maps and the fleet frontier.

## Scoped gate

`hack/verify-required-reply-transport.sh` owns only the previously absent
`unf-required-reply-qualification` Namespace. It does not flip the cluster-wide
encryption baseline, change key timers, lower links or replace agents. Three
non-root, tokenless, resource-bounded fixture Pods place two clients on one
worker and a server on the other. Namespace-wide ingress/egress isolation
permits only requests to the server's TCP/8080 and UDP/5353 listeners. A
bidirectional EncryptionPolicy selects only one client/server pair.

Before testing, the gate verifies exact runtime versions, fixture placement,
32 policy outcomes, complete agent revision adoption and a single fleet-wide
active encryption generation. Both selected Nodes require real epochs; idle
Nodes remain Native. The replying Node's public admitted plan must carry the
schema-2 initiating identity pair at the exact active generation/policy revision.
Missing authority is not replaced by a Native exception. Private key files are
never read.

The matrix requires 12 Required and 12 Native TCP/UDP request/response successes
across IPv4/IPv6 PodIPs, Services and translated Service ports, followed by
eight unsolicited reverse-direction denials. Listener health is established
first. An exec failure is not a denial; traffic probes are not retried to hide
loss. A tokenless, no-host-mount capture on the explicit underlay interface
requires WireGuard frames, zero selected-client plaintext, positive Native
plaintext, clean explicit stop and zero reported kernel capture loss. Existing
capture negative tests cover premature expiry, crash and unavailable statistics.
The fixture Namespace must then be positively absent and every agent back on a
converged Native generation before evidence can say `passed`.

The gate's generation/provenance checker has 20 explicit negative mutations;
`bash hack/verify-required-reply-gate.sh` passes those and capture checks.
This is not yet a live platform result. Same-Node Required locality, local/remote
replicas, complete lifecycle requalification and S1–S5 remain separate gates.

Example cl02 invocation after successful candidate deployment:

```sh
KUBECONFIG=.tools/cl02-audit.kubeconfig \
UNF_REQUIRED_REPLY_RUNTIME_REVISION=67c27727d92e86332298724e399b9b6e63f0c6af \
UNF_REQUIRED_REPLY_INFRASTRUCTURE=cl02-st7gq \
UNF_REQUIRED_REPLY_CAPTURE_INTERFACE=br-ex \
UNF_TEST_TOOLS_IMAGE=quay.io/arencloud/unf-test-tools-dev@sha256:e9cce439d92d0f7d3d6751f234e397a7efc29f9983bc0ae8fc318432c4ff2352 \
UNF_REQUIRED_REPLY_DIAGNOSTICS=.artifacts/required-reply-cl02-new-run \
timeout 1200 bash hack/verify-required-reply-transport.sh
```

Kind uses its exact kubeconfig/context and physical underlay interface after
cl02 passes; it must run matching immutable images. No cluster reset or
destructive state cleanup is part of this workflow.
