# ADR 0434: Paired main locality bridge qualification

Date: 2026-09-21

Status: verified isolated main-program gate; live composition remains open

The clean `98ca1a7` diagnostic passes cl02 first, then persistent Kind on the
identical immutable image:

`quay.io/arencloud/unf-test-tools-dev@sha256:5b8ba9562023323f90f3fcecb15c69575f2449db89a3ae6adde10a722f1a6fba`

Each platform executes five exact tests: compiled revision equality, existing
encryption finalization, armed locality fence with missing-bank fallback,
source-egress precedence and dual-stack DSR. Actual main programs and all
continuations load into the kernel and run through BPF_PROG_TEST_RUN. No live
TC attachment or selected-bank packet delivery is claimed. Reverse-Service
changes in the working checkout are deliberately excluded from this image.

Compiled revision is `98ca1a750c7db9b51cbe09bf5dc4e6812bc2e920`.
The test binary SHA-256 is
`fa9356e81b0c6a824ffc1c52efa53e84e68fe78b5ebfc07183408e71923933e2`;
the main ELF is
`498c413dd728fa8f60455c0fdb7cdc0551e8476b41faa844e9386edbb77dd807`.
Processes exit zero without restarts; exact-UID namespace cleanup passes.
The first local invocation refused the dirty working directory before creating
any gate resources; the actual runs use the clean source checkout.

Both production fleets remain `45d85d5`, Ready with zero restarts. Existing
journals are byte-identical, including Kind's unchanged absent control-plane
journal. No production keys, maps, journals or release pins were reset.

Current regular/init and retained/rotated regular/init logs were reviewed on
both platforms, including the Kind controller. Observation, size and complete
JSON checks pass, with no ERROR entries. cl02 has 475 current WARNs: 443 bounded
flow-history retention, 19 peer-proof retries, five topology retention, three
qdisc attempts, three key-publication retries and two attach failures. The
attach failures precede this gate and report ENODEV for `unp0019a88d4418`;
they are retained, not silently dismissed as healthy operation. Key publication
returns HTTP 400 and testimony retries HTTP 503; lifecycle requalification
must address their impact. Retained cl02 files contain 6,767 WARNs across 22
categories. Kind has two current peer-proof WARNs and 70 retained WARNs across
12 categories. This is not a warning-free or heavy-load stability claim.

Evidence roots: `.artifacts/p9-kernel-main-bridge-98ca1a7-{cl02,kind}` and
`.artifacts/p9-main-98ca1a7-*` (including `kind-all-retained`).

| Artifact | SHA-256 |
| --- | --- |
| cl02 result | `7a720bf76bd0036608259c20de8d7d56f948fce61df5468d27f4acdc96aa05f2` |
| cl02 test log | `854fcbc1f28825f8ad41027b3d1e2c50af192e55ff6fb0f2192be648ec5cc055` |
| Kind result | `5dacb6605a621a470f0fea096b481e3659141e4d46877b21474840636c4201e6` |
| Kind test log | `f2522f10e3852ae38c293b6daf526656e54bcbf52816085893e56d23672414f4` |

Next: reverse-Service policy/transport composition, then actual publisher,
writer and selected-bank delivery, mixed replicas and recovery. L3/L4/L5/Q and
S1–S5 remain open; this gate does not promote the platform or phase rows.
