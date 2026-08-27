# Platform and version support matrix

The machine-readable source of truth is
[`support-matrix.json`](support-matrix.json). It uses schema version 1 and is
validated by `make support-matrix-check`.

“Qualified” applies only to the complete tuple in one row: platform release,
Kubernetes version, OS, kernel, architecture, runtime, CNI, address families,
attachment mode, cluster shape, and evidence revision. It does not mean that a
nearby version or platform is supported by inference. A recorded pass remains
historical evidence for that tuple even if a lab credential expires or a lab
cluster is later rebuilt; a new run must add or update a row rather than silently
refreshing the old result.

## Qualified tuples

| Fixture | Platform | OS and kernel | CNI/families | Attachment | Evidence |
|---|---|---|---|---|---|
| Kind | Kubernetes 1.35.0 | Debian 12 node / Fedora host, Linux 7.1.4, amd64 | kindnetd, IPv4/IPv6 | TCX and legacy netlink | `9dc6023`, Kind endpoint/scale/recovery/upgrade gates |
| cl01 | OpenShift 4.22.9 / Kubernetes 1.35.6 | RHCOS 9.8, Linux 5.14, amd64 | OVN-Kubernetes, IPv4 | legacy netlink | `4f213c7`, adaptive OpenShift endpoint gate |
| cl02 | OpenShift 4.22.9 / Kubernetes 1.35.6 | RHCOS 9.8, Linux 5.14, amd64 | OVN-Kubernetes, IPv4/IPv6 | legacy netlink | `9a376ae`, endpoint and digest-pinned transition gates |

The JSON record contains the exact runtime versions, full Git revisions,
commands, result/ADR references, and scope for every row. Its explicit
`unsupported_boundaries` section is normative: unlisted Kubernetes/OpenShift
releases, kernels, architectures, CNIs, cluster shapes, and production artifact
paths remain unqualified.

The next matrix exit requirement is a fourth row for an additional Kubernetes
or OpenShift release. That row must pass enforcement, recovery, and upgrade on
its actual kernel/attachment tuple before milestone 4 can be marked Verified.
