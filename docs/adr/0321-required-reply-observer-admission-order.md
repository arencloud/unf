# ADR 0321: Admit the Complete Required Reply Fixture

Date: 2026-09-13

Status: local gate regressions pass; corrected cl02 qualification pending

The fourth instrumented cl02 run of runtime `67c2772` passes 12 Required
requests, then fails the first Native IPv4 TCP control. Paired zero-loss
captures show its SYN (`10.128.0.13:50068` → `10.128.4.17:8080`) leaving the
source and entering destination `ens18`, without reaching the server veth.
At Unix time `1789315723.323`, destination policy revision is 547 while its
encryption policy revision remains 543; the SYN arrives at `1789315723.825`.
Source samples remain aligned at 543. The destination mismatch persists
through the retransmission. This supports the existing fail-closed revision
fence, not an attributed connection-map failure. One-second samples are not
per-packet instrumentation and do not retrospectively attribute earlier runs.

The qualifier itself creates its host-network capture Pod, ServiceAccount,
RBAC and namespace security label *after* its final adoption barrier. Those
mutations invalidate the assumption of a fully admitted, unchanged fixture.
Prepare the complete observer before policy and Required-generation adoption.
Its tokenless, bounded capture container waits up to 600 seconds for an
emptyDir signal, then replaces PID 1 with the existing 300-second tcpdump
watchdog. Starting capture after admission uses only exec into the owned
emptyDir; it does not mutate Kubernetes objects. Explicit stop, zero-loss
validation and normal Namespace cleanup remain mandatory. No packet retry,
map reset, journal reset, policy bypass or longer traffic timeout is added.

Failure handling now announces the original failure immediately to bounded
read-only observers and retains the public flow history, agent state and
encryption status before cleanup. Each read has the existing 15-second API
bound and its own exit/error evidence. An observer error cannot become an
empty-map/empty-history claim or suppress later readbacks. The previous
ignored map reader handled only IPv6 UDP and correctly failed, rather than
pretending it inspected this IPv4 TCP tuple.

Local gate checks cover ordering, bounded capture lifecycle and public API
readback failure isolation. The fourth run's fixture and observer Namespaces
are absent; all five agents converge again. All six UNF Pods and installer
containers have zero restarts. The retained 20-minute log window has no ERROR,
panic, OOM or verifier rejection; plan/proof retries, one key publication
warning, a Service synchronization warning, topology persistence retry and
bounded history-retention warnings remain visible.

This is a qualification correction, not production churn continuity or a
dataplane repair. Re-run the complete scoped reply gate on cl02 before Kind.
Required locality/replicas, full lifecycle requalification and S1–S5 stay open.
S4 must address the real cross-domain update fence without weakening authority.
Raw diagnostics remain ignored under `.artifacts/`; no credentials are recorded
in Git.
