# OpenShift primary-CNI installation inputs

These files are installer inputs for a new, disposable OpenShift 4.22 cluster.
They are not a Kustomize overlay and must never be applied to a running OVN
cluster.

Use `install-config-networking.yaml` as the networking section of the new
cluster's install configuration and include
`manifests/cluster-network-03-config.yaml` in its installer manifests. The
resulting cluster deliberately starts with no vendor default CNI, standalone
kube-proxy enabled, and Multus disabled. UNF bootstrap manifests, digest-pinned
images, exact MachineConfig ownership, and a tested no-CNI teardown must be
complete before using these inputs.

Run the read-only eligibility check against any candidate API:

```bash
OPENSHIFT_KUBECONFIG="$PWD/.tools/cl02-audit.kubeconfig" \
  make openshift-primary-cni-preflight
```

The command must pass before any UNF primary-CNI installation. A failure on an
OVN-installed cluster is expected and must not be bypassed by deleting the
Cluster Network Operator's applied-state ConfigMap.
