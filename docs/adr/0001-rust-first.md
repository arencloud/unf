# ADR 0001: Rust-first implementation

Status: Accepted

## Context

UNF spans Kubernetes reconciliation, host networking, CLI tooling, and eBPF. A
single strongly typed language reduces translation boundaries and enables shared
ABI definitions.

## Decision

Use stable Rust for userspace and Rust/Aya for the initial eBPF program. Introduce
another implementation language only after an ADR demonstrates a concrete
compatibility or reliability blocker.

## Alternatives

Go for the control plane plus C/libbpf for eBPF is mature but creates additional
domain and build boundaries. C throughout offers kernel familiarity at a greater
memory-safety and application-development cost.

## Consequences

Normal development pins stable Rust. Unsafe code is denied in the host workspace;
target-specific BPF unsafe operations require local safety comments. Rust library
quality and ecosystem compatibility become important project dependencies.

## Open questions

Whether future kernel features require a small libbpf-rs or C compatibility module.
