# Agent-based cl02 installer inputs

This directory is the versioned, non-secret source for rebuilding the five-Node
cl02 lab with the OpenShift Agent-based Installer. It is specific to the audited
hardware and network:

- three control-plane Nodes and two workers, all installed to `/dev/sda`;
- VLAN 600 over `ens18`, exposed directly as the `br-ex` native UNF uplink;
- IPv4-first dual-stack machine, cluster, Service, API, and ingress networks;
- exact hostnames, MAC addresses, and addresses retained for the versioned UNF
  Node-block map; and
- `10.50.60.200` as the rendezvous address.

`install-config.yaml.example` intentionally contains no credentials. The local
ready-to-use copies are mode 0600 and Git-ignored under
`.tools/openshift-primary-cni-install/`. Never commit a populated OpenShift pull
secret or SSH key.

The Agent-based Installer consumes its input files. Copy the two protected files
to a new installation directory before each image build. With the OpenShift
4.22.10 installer used for validation:

```bash
install_dir=/path/to/new-cl02-install-directory
install -d -m 0700 "$install_dir"
install -m 0600 \
  .tools/openshift-primary-cni-install/install-config.yaml \
  "$install_dir/install-config.yaml"
install -m 0600 \
  .tools/openshift-primary-cni-install/agent-config.yaml \
  "$install_dir/agent-config.yaml"

openshift-install agent create cluster-manifests --dir "$install_dir"

yq -i '.spec.networking.networkType = "None"' \
  "$install_dir/cluster-manifests/agent-cluster-install.yaml"
install -d -m 0700 "$install_dir/openshift"
install -m 0600 \
  deploy/openshift-primary-cni/manifests/cluster-network-03-config.yaml \
  "$install_dir/openshift/cluster-network-03-config.yaml"

openshift-install agent create image --dir "$install_dir"
```

The explicit generated-manifest edit is required because OpenShift 4.22.10
retains `OVNKubernetes` in the visible AgentClusterInstall field even though it
preserves the `networkType: None` install-config override. The custom Network
manifest is also required by Assisted Service for the `None` network type. Do
not omit either step and do not boot an ISO until this sequence completes.

This exact sequence was validated through creation of a 1.42 GB agent ISO. The
installer consumed all five NMState definitions, the patched `None` selection,
and the extra Network manifest. This is a development qualification path, not a
Red Hat support claim for UNF.
