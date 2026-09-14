# ADR 0366: cl02 Device-Lease Ownership and Admin-State Gate

Date: 2026-09-14

Status: verified for the expanded isolated serial mechanism; Kind pending

Source `27efd6e` passes the expanded cl02 fixture on immutable image
`quay.io/arencloud/unf-test-tools-dev@sha256:a06fdaf5d71fb811e3a7376dc863c0e2dad068ec28a78ff745601c681b35d6c9`.
Anonymous registry inspection confirms the full source label. Diagnostic object
SHA-256: `d74d24720e08886870fa6e64e582068b74534d2f6915d81bd1c5f61e0a7e2558`.

At 01:11:24 UTC all 62 IPv4/IPv6 attempts finish with 28 exact application
deliveries and 34 ready-receiver timeout denials. Every denied probe is rejected
by the classifier and every counter readback matches. The real CNI derivation
produces maximum-length 96-byte aliases from synthetic UID/nonce-bound fixture
records. Missing and modified aliases at all four endpoints, digest/role changes
and a longer alias sharing the complete valid prefix are rejected. Restoration
recovers the positive controls. Host and peer administrative-down cases are
rejected before redirect is requested.

The previous namespace-movement, host rename, explicit rebind, configuration
and deletion/index/MAC reuse cases also pass. Recreated targets additionally
clone the original aliases; equality still does not implicitly rearm the device
map. This is not a live CNI attachment/placement authentication test: the record
adapter and private manually created pairs remain diagnostic inputs.

The RHCOS verifier accepts both programs, including bounded string reads and
complete aligned-word comparisons. Translated/JIT sizes are 9,872/6,149 bytes
for redirect and 5,664/3,548 for seed. These are not CPU or throughput figures.
Flags/alias-pointer/string offsets are checked as 176/312/16 from running BTF.

Evidence: `.artifacts/p9-device-lease-27efd6e-cl02`; raw archive SHA-256
`bd699023a110348adc4de9648cdb774cb64869de891ced784d86c67f4fe1f169`.
All private resources and the Kubernetes fixture Namespace are removed; Node UID
is preserved. The first final read catches policy 471→472 reconciliation; the
next retained read confirms all five reports fresh/converged at policy 472 /
Service 203. UNF containers remain Ready with zero restarts; runtime is `f984db9`.

Controller, every agent and installer logs are reviewed before, during and
after. The final complete window is below its cap and contains 396 bounded
flow-history warnings, two proof-assistance retries and two topology-history
warnings, without live UNF ERROR, panic, OOM or verifier rejection. Warnings
remain stabilization findings. No history, journal or frontier is reset.

The identical image must pass retained Kind next. Concurrent lifetime,
non-transmitting context acquisition, immutable publication, real address/
attachment/placement joins, packet composition and production consumption remain
open. This does not enable locality admission or close full Phase 9/S1–S5.
