# ADR 0355: Held Namespace Veth Observations

Date: 2026-09-14

Status: implemented and locally verified; isolated cl02 then Kind pending

The locality consumer needs to retain the exact namespace objects used for
independent attachment readback, not just their pathname or observer-relative
interface numbers. `VethPlan::observe` now returns an opaque `VethObservation`
holding both namespace descriptors and a strict reciprocal veth snapshot.
Construction verifies that the host calling namespace and current peer path
still match the retained descriptors. There is no public unchecked constructor,
deserialization, implicit clone, kernel-admission flag or durable capability.

Rechecks open netlink observations against those retained descriptors and
compare every original link coordinate. Namespace path replacement/removal,
changed calling namespace, read failure or snapshot drift permanently retires
the observation and releases both descriptors. Restoring the link/path does
not rearm it: a new explicit observation is required. Recheck takes ownership
of the descriptors before its first suspension, restoring them only on success;
cancellation after it starts therefore also drops them and leaves it retired.
Borrowed descriptors cannot outlive the owning observation and are unavailable
after retirement. The original snapshot remains historical readback only.

Ordinary CNI `readback` uses the shared strict reader without allocating the
long-lived observation or cloning its snapshot. No journal schema, BPF map,
runtime protocol, live image or packet permission changes in this slice.
Successful namespace retention prevents namespace-object reuse while held;
it does **not** prevent veth movement/deletion, route drift or interface-index
reuse. An unobserved move-and-restore between checks is not detected by this
API. It is not the continuous packet-time lifetime fence still required by L3.

Three new local tests cover descriptor identity and duplicate retention, all
eight link snapshot coordinate groups, and sticky failure retirement. The
workspace passes 807 tests with 26 explicitly ignored privileged tests; strict
workspace Clippy and formatting pass. The example observer and isolated
qualification fixture exercise five positive observations, four exact drift
rejections (MTU, namespace-path replacement, peer move, target deletion), and
four sticky-retirement checks after restoration. Their platform result remains
pending; shell syntax validation is not a kernel qualification.

Next: build one immutable isolated fixture, run it on cl02 with before/during/
after UNF logs, then the identical retained-Kind image. Keep continuous source/
peer lifetime, authenticated banked consumption and Phase 9/S1–S5 open.

The first isolated image build stops before publishing or cluster mutation:
the new fixture script is absent from the explicit build-context allowlist.
Only that script is added; ignored credentials, private prompts and qualification
artifacts remain excluded. The corrected image must still pass both platforms.
