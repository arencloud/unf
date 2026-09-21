# Phase 9 persistent Kind lab

This is the independent environment approved on 2026-09-21 (ADR 0388), not a
replacement for historical retained-state evidence. Qualification order remains
**cl02 first, then Kind with matching immutable images**. Initial bootstrap used
the cl02-passing `f984db9` Native runtime. ADR 0391 subsequently qualifies the
scoped reply/inventory gate on `8db97bb`; neither result closes the full lifecycle.
ADR 0394 tests isolated `6d71a30` signal probes without upgrading the live fleet.
ADR 0396 subsequently upgrades the live fleet to those same images after cl02,
qualifying Native configured controller/agent recovery and the expanded
reply/inventory gate. Full locality and lifecycle qualification remain open.

Run commands from the repository root. The kubeconfig and TLS keys are local,
ignored credentials; never include them in commits or evidence bundles.

```bash
kubectl --kubeconfig .tools/kind-unf-p9-20260921.kubeconfig \
  --context kind-unf-p9-20260921 get nodes
sudo -n hack/phase9-kind-persistent-podman.sh ps -a
bash hack/verify-phase9-persistent-kind.sh .artifacts/p9-kind-new-observation
```

The verifier needs a new, nonexistent evidence directory, checks only bootstrap
readiness and writes no cluster state. Defaults pin ADR 0388's revision and CNI
hash; future qualified runtime checks must explicitly set
`UNF_BOOTSTRAP_REVISION` and `UNF_BOOTSTRAP_CNI_SHA256`. It does not replace
traffic, ciphertext, locality, lifecycle, restart or scale gates. Review every
UNF regular/init/previous container log separately, with observer failures and
truncation treated as gaps.

## Storage and restart boundary

Always use the dedicated wrapper. Default `sudo podman` refers to other lab
clusters and must not be used to manage this one. The wrapper selects:

- Durable graph root: `/var/lib/unf-kind/phase9-20260921/storage`.
- Durable network config: `/var/lib/unf-kind/phase9-20260921/networks`.
- Volatile runtime state: `/run/unf-kind-phase9-20260921`.
- Network `unf-p9-20260921`, bridge `unfp9br0`, IPv4 `10.90.91.0/24`, IPv6 `fd90:91::/64`.

The create operation used `.tools/bin/kind`,
`hack/kind-service-fabric-config.yaml`, provider `podman`, and an isolated PATH
whose `podman` resolves to the wrapper. `KIND_EXPERIMENTAL_PODMAN_NETWORK` selects
the dedicated network; Kind explicitly warns that this override is unsupported.
Do not silently switch to the default network/store.

After a workstation reboot, inspect the existing containers first. Do **not**
rerun `kind create`, delete containers, prune volumes or reset authority journals
to recover the cluster. No automatic-start service was installed. If these
exact containers are stopped, their intended manual start is:

```bash
sudo -n hack/phase9-kind-persistent-podman.sh start \
  unf-p9-20260921-control-plane unf-p9-20260921-worker unf-p9-20260921-worker2
```

Host `fs.inotify.max_user_instances` was raised from 128 to 1024 for this session
only; the repository prerequisite is at least 512. Recheck it after reboot and
restore that prerequisite before starting the lab. Persistent graph storage is
verified, but post-reboot mounts, networking, BPF recovery and unchanged Node
UIDs still require a real recovery gate. Failures must be investigated without
state resets. The first-install `configure-kind-primary-cni.sh` is **not** a
restart script: it deliberately rejects existing CNI configuration.

The bootstrap overlay is locally retained at
`.tools/phase9-kind-20260921/bootstrap`; it overrides the Phase 9 layer's default
Required baseline to Native, pins public image digests and bootstraps controller
DNS host aliases at `10.90.91.4`. Verify the current API Node address before
future deployment; do not blindly reuse this address in another cluster.
