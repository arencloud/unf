# ADR 0362: Isolated Two-Ended Device Lease Experiment

Date: 2026-09-14

Status: implemented diagnostic; cl02-before-Kind qualification pending

## Decision

Investigate a reference-backed local-delivery path, separately from the live
packet program. The previous drop-only readback gates establish current device
and peer namespace observations, but do not prevent a cached target pointer
from becoming stale or an interface index from referring to a replacement.

Linux device maps acquire a device reference, remove bindings on unregister,
and defer entry reclamation/device release through RCU. The verifier permits
device-map lookups, independently of XDP redirect use. These are the properties
being investigated, not an assertion that an entire UNF delivery proof follows
automatically. See the primary [device-map implementation](https://github.com/torvalds/linux/blob/v5.14/kernel/bpf/devmap.c)
and [map/helper compatibility checks](https://github.com/torvalds/linux/blob/v5.14/kernel/bpf/verifier.c).

The isolated classifier requires both source and target device-map bindings
before using a target pointer captured from that device's own TC context. It
checks actual host and peer indices and independently established namespace
cookies at both ends. Only then does it rewrite the Ethernet addresses and
request `bpf_redirect_peer`. The kernel's peer redirect checks the target peer
and administrative-up state; namespace movement includes network synchronization.
See [redirect implementation](https://github.com/torvalds/linux/blob/v5.14/net/core/filter.c)
and [device movement](https://github.com/torvalds/linux/blob/v5.14/net/core/dev.c).

The intended lifetime argument is an inference requiring further audit: a
successful immutable device-map lookup protects the associated device through
the invocation's RCU read-side interval, while unregister invalidates the
binding before later index reuse. A pointer seed and map incarnation must be
paired without replacement races. Production bank publication and the interval
through actual redirect consumption are not yet qualified by this experiment.

## Scope and verification gates

The separate example, loader mode and fixture use only owned disposable veths,
four private network namespaces and private bpffs/maps. The target-pointer map
is never dumped into result evidence. No live UNF binary, map, interface,
generation, attachment journal or encryption authority is changed.

The planned serial IPv4/IPv6 gate requires sixteen positive application
deliveries and fourteen exact denied attempts. Thirty per-probe counter checks
distinguish eighteen requested redirects from twelve classifier rejections;
two requested redirects must not deliver while the target peer is down.
Cases include rename, both peers' namespace move/return, target-host move/return,
deletion/recreation with identical indices and MACs, explicit reseeding and
invalid configuration. Receivers must be ready before sending; denied reception
requires the expected timeout, empty payload and the exact attempt counters.

This is not authenticated CNI/locality authority: no address/UID/nonce alias
binding, policy/Service/egress composition, concurrent table publication,
continuous-movement stress, host administrative-down enforcement or measured
performance claim is included. The serial fixture explicitly rebinds a private
slot only while its sender is idle; production must use immutable incarnation
entries and verified publication/retirement. Returning a peer to its original
namespace is not sticky retirement or proof that no intermediate move occurred.

Local BPF compilation, loader checks and the existing two-positive/32-negative
layout regression precede immutable-image execution on cl02, then retained
Kind. A result cannot be called verified until payloads, all counters, namespace
cleanup, Node identity and controller/all-agent/installer logs pass. Full Phase 9,
L3 consumption and stabilization S1–S5 remain open.
