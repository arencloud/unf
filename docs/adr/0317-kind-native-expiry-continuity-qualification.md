# ADR 0317: Matching Kind Native Expiry and Continuity Qualification

Date: 2026-09-13

Status: bounded Native/churn slice verified cl02 first, then retained Kind

## Matching runtime, retained state

After ADR 0316's cl02 pass was committed and pushed, retained
`unf-s1-571379d` receives runtime `5ea1bd2b759915edae0fe674863c5b3e9ebefb24`.
The OCI archives preserve the exact published controller/agent manifest digests
from ADR 0314. Every Node's imported tag/digest is checked before deployment.
The controller is replaced first, then each agent is replaced and independently
version-verified. The original three Nodes, maps, journals and frontier remain;
no cluster recreation, state reset or broad cleanup manufactures recovery.

The pre-rollout frontier has three receipts at generation `1789280113084`.
The four replacement UNF Pods become Ready with zero restarts, and the serial
agent updater restores the normal RollingUpdate strategy afterward.

## Qualification

Qualifier `c36bd929f09f28d27ada30411d6263235e11e182` passes the identical
24 TCP/UDP allow cases and eight unsolicited reverse denials across IPv4/IPv6,
same/cross-Node, PodIP, Service and translated Service ports. Empty Namespace
create/relabel/delete continuity produces 720 fresh HTTP samples, zero failures,
90 samples per each of eight paths, complete before/during/after coverage,
unchanged policy revision 34 and three skipped invalidations. Cleanup proves
both owned Namespaces absent and all three agents converged.

| Record | SHA-256 |
|---|---|
| Native evidence JSON | `8b1a101811b798c76ec413e616e23f01265344387158bdbd025d68823cf1743a` |
| Continuity summary | `0ddfe1a91d1f070956116d6988dabec7cc0881744e7698da762aa6c19d5e51a0` |
| Fresh-connection records | `79d27b290e7c853e5d677e088352c7198ae85091089906fcf5ce1cd2e10cee8b` |

Evidence remains ignored under `.artifacts/s1-verifier-5ea1bd2-*`. Release
metadata's full Kind qualification stays pending: this bounded Native gate
is not the larger ciphertext/rotation/replacement/history lifecycle gate.

## Log review and remaining work

All current containers are reviewed with zero restarts. Kind's per-packet INFO
volume exceeds the first 2-MiB review cap and then a 16-MiB expansion on one
worker; CRI rotation also replaces current log files. The audit therefore
collects the retained rotated agent logs directly from the three owned Kind
Nodes, without changing logging configuration or accessing authority keys.
These records show four startup-admission warnings, four peer-testimony
warnings and one rejected-plan warning, but no ERROR, panic, OOM, verifier
rejection or stopped-dataplane entry. Controller/installer logs are also read.
Log amplification/rotation is an S1/S3 finding, not hidden by a bounded tail.

This closes the Native expiry/empty-Namespace continuity slice on both platforms,
not Phase 9 or S1–S5. Next are address/locality-bound Required transport for
same-Node/replicated identities and policy-tracked replies, then complete
current-runtime lifecycle qualification on cl02 before Kind. Arbitrary
policy/Service update continuity, active reverse-key collisions, map pressure,
long-duration load and resource-versus-load curves remain explicit boundaries.
