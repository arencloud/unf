# ADR 0432: Policy-first locality forward bridge

Date: 2026-09-21

Status: implemented and locally checked; kernel/runtime qualification pending

The actual main TC finalizer now prepares the fixed-width locality input only
after packet policy, Service frontend handling and explicit egress ownership.
It requires a structurally valid admitted encryption cut, current policy and
Service revisions, matching active identity configuration and the applied
locality fence. A wholly empty/quiescent admitted cut is structurally valid,
but remains **inactive for ordinary transport**; it cannot create an implicit
Native decision. Local delivery still requires the complete sealed bank.

Original pre-Service-SNAT source ownership and the final selected backend come
from the policy observation. Ports come from the actual post-translation wire
tuple. The bank independently verifies placement, incarnation leases, devices
and actual route/MAC ownership before redirect. A missing bank or bank miss
resumes the existing ordinary encryption selection; it never grants Native.

Four versioned resume entries are installed in the already owned locality map,
without changing the existing twelve-slot core tail array. Normal resumes start
after the policy/Service/egress preamble. Local DSR uses a separate reversible
NAT continuation, rebuilds input and re-enters the bank for every check again.
Missing NAT continuation or withdrawn selection cannot return a blind PIPE.
Top-level dispatch avoids retaining an extra BPF subprogram stack frame across
tail calls or ordinary transport selection.

The next isolated `kernel-main-bridge` gate loads the actual main ELF and all
continuations with four exact existing/expanded agent test cases: ordinary
encryption, armed locality fence with missing bank, source egress precedence,
and dual-stack DSR. It checks that exactly one test actually ran per invocation.
It uses anonymous maps and BPF_PROG_TEST_RUN, not live TC attachment or packet
delivery. The diagnostic limit is two CPUs/2 GiB for repeated full-map test
allocation, not a production resource requirement or stabilization result.

Local verification: 909 workspace tests pass, 27 explicitly ignored (including
the new privileged bridge case); strict all-target Clippy and main BPF release
compilation pass. Shell syntax/formatting checks pass. The new immutable image
must pass cl02 before identical-image Kind. Successful compilation does not
establish verifier acceptance or packet correctness.

Reverse-Service early-return policy/transport composition remains an explicit
gap, as do actual selected-bank delivery through the main hook, complete
publisher/writer integration, crash-stage cleanup, restart continuity and
L3/L4/L5/Q. Do not roll this partial bridge onto the live fleet or promote the
phase based on this isolated gate. Both production fleets remain `45d85d5`.
