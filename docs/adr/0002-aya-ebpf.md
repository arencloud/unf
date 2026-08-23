# ADR 0002: Aya for the initial eBPF dataplane

Status: Accepted for Phase 1; revisit after compatibility testing

## Context

The first dataplane milestone observes IPv4 TCP/UDP flows on clusters that retain
their existing CNI. It needs a Rust loader, TC programs, maps, and ring buffers.

## Decision

Use Aya 0.14 in userspace and aya-ebpf 0.2 for separate ingress/egress TC
classifiers. Build the kernel package outside the host Cargo workspace for the
dedicated BPF target. Isolate nightly plus `rust-src` to that build only.

## Alternatives

libbpf/libbpf-rs has broad kernel tooling and CO-RE history but adds a C/clang
artifact boundary. XDP is too early because Phase 1 needs compatibility rather
than earliest possible NIC handling. cgroup hooks do not cover every existing-CNI
path needed by the initial observation experiment.

## Consequences

Shared ABI types still compile and test on stable. Kernel compatibility, verifier
behavior, and OpenShift/RHCOS support remain validation requirements. A full Aya
object load was not proven merely by compiling userspace.

## Open questions

BTF/CO-RE coverage across supported kernels, pinned-map upgrade behavior, and
whether any critical hook/helper requires libbpf-rs.
