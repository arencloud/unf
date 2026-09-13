# ADR 0329: Matching Kind CNI Workload Ownership Qualification

Date: 2026-09-13

Status: isolated CNI ownership slice verified on cl02, then retained Kind

After ADR 0328's complete cl02 gate and pushed result, the identical immutable
test image passes on retained `unf-s1-571379d`. No cluster recreation, journal
reset, live runtime replacement or BPF-state change is performed.

The source is `d3207e37d4da861b856db30a0784835b99f8d7cb`; the test image is
`quay.io/arencloud/unf-test-tools-dev@sha256:c56c2c3e9a06fc6333b8b4bacee969346488241ab9a0cc479677e7ba51d66d7d`.
The independent Kind result has the same adapter and JSON hashes as cl02:

- Adapter: `892e6117910ff3c9d432f00c41308e48593ff098ac1f55a0b6ac1ec39fd02308`.
- Result JSON: `e0964143dcb854b25fa05ac94be792dd8b5010281f07a85255d284966e962a83`.
- Kind fixture archive: `5de0cbca68330f10ece9e32f7886adf5a44c90da1bdae6d44f6429888119c341`.

The exact worker UID remains `c5c2bc2c-b272-46b5-943e-c81418307749`, on
Debian 12, kernel `7.1.4-204.fc44.x86_64`, containerd 2.2.0 and Kubernetes
1.35.0. Eleven expected, diagnostic-checked rejections pass alongside legacy
replay, bound ownership, independent-process restart, dual-stack route/alias
drift and recovery, normal deletion, same-address/different-UID reuse and
positive fixture cleanup. The tokenless test Pod has zero restarts; its
namespace is absent after cleanup.

Controller, every agent and installer logs are reviewed around the run. Recent
20-minute windows fit the per-file limits and contain no WARN/ERROR. Expanded
agent CRI readback during validation retains 71,629 lines / 42,139,266 bytes
across current and rotated files, including an observed control-plane rotation.
It retains earlier 14 proof-assistance, six activation, four synchronization,
one egress-request and one flow-export warnings, all before this qualification.
No ERROR/panic/OOM/verifier rejection or stopped-dataplane match is found in the
retained windows. All UNF Pods remain Ready with zero restarts. This is neither
complete historical-log coverage nor a clean operational-history claim; log
amplification and the earlier request failures remain S1/S3/S4 findings.

## What remains open

Both live fleets still run `67c2772`; the new CNI binary was used only inside
the isolated test containers. This gate does not test a live CNI rollout or
runtime-supplied real Pod UID capture, and does not grant locality permission.
Interrupted pre-seal creation remains fenced rather than automatically adopted.
L3 still needs that recovery/rollout boundary, authenticated attachment and
route binding, banked distribution and actual packet-time enforcement.
L4/L5 Required locality/replicas, Q full Phase 9 lifecycle and stabilization
S1–S5 remain open. Phase 9's two full platform rows remain Reopened.
