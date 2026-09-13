# ADR 0322: cl02 Required Reply Qualification

Date: 2026-09-13

Status: scoped cl02 gate verified; matching Kind next

Runtime `67c27727d92e86332298724e399b9b6e63f0c6af`, qualifier
`6400f37d57edc5a1e4223c966f2a2d4013eb9af8`, passes the corrected
`hack/verify-required-reply-transport.sh` on dual-stack cl02, UNF primary CNI,
RHCOS/SELinux, with two separate workers and no kube-proxy. The cluster baseline
stays Native; only the owned fixture pair is selectively Required.

- All 32 policy explanations and the exact fleet generation/reply provenance
  pass before traffic. Schema-2 replies retain the allowed initiating pair;
  no reverse new-flow permission is synthesized.
- Twelve Required and twelve Native requests pass across IPv4/IPv6, TCP/UDP,
  cross-worker PodIP, Service and translated Service ports.
- Eight independently initiated reverse flows remain denied. Each workload
  probe executes once; listener readiness checks are separate.
- Physical `br-ex` capture contains 136 WireGuard frames, zero Required
  plaintext frames and 72 positive Native plaintext control frames. Explicit
  stop exits zero with zero reported kernel capture loss. Both additional
  paired textual observers also report zero kernel loss.
- The fixture Namespace is absent, all five agents converge to Native
  generation `1789316503339` (policy 582, Service 253, egress 38), and every
  public recovery record has no pending generation and no epochs. Both
  diagnostic observer Pods and their owned Namespace are subsequently removed.

Evidence JSON SHA-256:
`2940fb63cd3131804f083ebf796bcd06713526d57a7f9c4ed0b6f1b2362cacba`.
Capture SHA-256:
`82566b956714f37ddec408016d817c57b02eaca7876752ca3fe74142f569ae85`.
Raw evidence remains ignored in
`.artifacts/p9-required-reply-67c2772-cl02-admitted-capture/`.

All UNF Pod/installer logs were reviewed in a bounded 20-minute window. No
ERROR, panic, OOM or verifier rejection appears; zero restarts are retained.
Key catch-up and plan/proof synchronization retries, clsact-already-present,
history retention and the previously recorded Service/topology warnings are
not hidden. This is not a healthy-operator or sustained-load claim.

The four earlier failed runs remain recorded in ADRs 0320–0321. Correcting
observer admission ordering isolates this steady-state slice; it does not
prove arbitrary policy/Service churn continuity or retrospectively explain
every earlier failed tuple. No authority check or persistent state was reset.

Next: matching-image retained Kind, then Required same-Node/replicated-identity
coverage and complete current-runtime lifecycle qualification, cl02 first.
Phase 9 platform rows and S1–S5 remain open.
