# OpenShift primary-CNI installation inputs

These files are the bounded reinstall package for a new, disposable OpenShift
4.22 cluster. They must never be applied to a running OVN cluster.

Use `install-config-networking.yaml` as the networking section of the new
cluster's install configuration and include
`manifests/cluster-network-03-config.yaml` in its installer manifests. The
resulting cluster deliberately starts with no vendor default CNI, standalone
kube-proxy enabled, and Multus disabled.

For an Assisted Installer deployment:

1. Select OpenShift 4.22, dual stack, and `None (Custom CNI)`.
2. Keep the IPv4 family first and use the exact cluster and Service CIDRs in
   `install-config-networking.yaml`.
3. Upload `manifests/cluster-network-03-config.yaml` into the installer's
   `manifests` folder. Do not upload `runtime/` or `machineconfig/`.
4. Preserve the existing bare-metal host networking. The current cl02 audit
   confirms `br-ex` is the IPv4 and IPv6 default uplink with an MTU of at least
   1500 on the target shape.
5. Start installation and obtain the administrative kubeconfig when the API is
   available. The cluster is expected to wait for a CNI at this boundary.

For an Agent-based Installer deployment, use the exact five-host inputs and the
generated-manifest/custom-manifest sequence in `agent-based/README.md`. Do not
run `agent create image` directly from only the two input files: OpenShift
4.22.10 must have the generated AgentClusterInstall field set explicitly to
`None` and the custom Network manifest embedded first.

The versioned Node-block map is deliberately bound to the current five physical
Node names. If any Node name changes during reinstall, stop before activation
and update `node-blocks.json`; the deployer rejects a partial or different Node
set instead of guessing an allocation.

Before activating UNF, protect the kubeconfig with mode 0600, then run:

```bash
make openshift-primary-cni-package-check
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" \
  make openshift-primary-cni-audit

infrastructure=$(oc --kubeconfig .tools/cl02-audit.kubeconfig \
  get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" \
UNF_OPENSHIFT_PRIMARY_EXPECTED_INFRASTRUCTURE="$infrastructure" \
UNF_OPENSHIFT_PRIMARY_ACKNOWLEDGE_DISPOSABLE="$infrastructure" \
  make openshift-primary-cni-deploy
```

The deployment's candidate audit first allows only a missing-PodCIDR condition,
then validates and assigns the exact five-Node dual-stack map in
`node-blocks.json`. It applies
the forwarding MachineConfigs and waits for both pools, verifies the pinned
uplinks and SELinux, creates disposable TLS, labels the exact Nodes, and applies
the anonymously pullable digest-pinned
host-network controller and agent. The installer sidecar waits for the local
root-authenticated agent socket before atomically publishing the sole CRI-O CNI
configuration. It then verifies exact fingerprints and waits for every Node to
become Ready. Bootstrap does not depend on cluster DNS: the deployer pins the
controller to one control-plane Node, injects its exact IPv4 InternalIP as a Pod
host alias, and uses a dedicated certificate identity until ordinary DNS is
available.

Pinned development images:

```text
quay.io/arencloud/unf-controller-dev@sha256:b4df5645ac3a2ea9552f7a21d2d0d81c7d7c4aa1ea8355e2c6f304c2f2be3d56
quay.io/arencloud/unf-agent-dev@sha256:e94e58150d3bb8756ab3c298db7d36dd0b9a1bd7bec1ffc6bb03f6e986a60fb9
```

Run the read-only eligibility check against any candidate API:

```bash
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" \
  make openshift-primary-cni-preflight
```

Strict preflight passes after the explicit Node-block assignment, or immediately
when an installer has already populated the exact values. The deployer performs
that strict check before MachineConfig or CNI installation. Any other audit
failure, especially on an OVN-installed cluster, must not be bypassed by
deleting the Cluster Network Operator's applied-state ConfigMap. Live teardown
and reprovision recovery remain part of the qualification gate; this package is
not a production installer.
