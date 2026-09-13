# ADR 0351: Fail-Stop Rollout Log Inventory

Date: 2026-09-14

Status: observer source repaired locally; cl02 controller-only rollout retained

The first `f984db9` cl02 rollout runner contains an observer bug: its jq loop
binds a Pod but reads `.spec.containers` from the outer list. Materialization
fails inside a process substitution. The subshell reports failure, but the
parent shell continues and updates the controller image. This is a rollout
observer failure, not a passing preflight or an attributed runtime defect.

The runner is stopped before changing any agent/installer. The new controller
`unf-controller-7d949d4596-hbfhq` becomes Ready with zero restarts; all five agent
Pods remain on `450de80` with zero restarts. No journal, frontier, key, map or
cluster is reset, and no automatic rollback is attempted.

The old controller's pre-rollout API window and new controller startup logs are
retained. A first `/host/var/log/pods` check is inaccessible because that path is
not mounted; this is not absence evidence. A subsequent exact host-PID-root
check positively reaches `/proc/1/root/var/log/pods` and observes the old
controller's exact Pod-UID directory absent. Its final termination interval is
therefore unavailable, not silently claimed as reviewed. Earlier captures and
this failed rollout remain evidence. Future feature gates use a fresh complete
before/during/after validation window.

The shared rollout guard now materializes a complete validated log-target array:
Pod name/UID, Node, regular and init container coordinates, with duplicate and
missing-coordinate rejection. Callers must check this command in the foreground
and save its output before starting loops or making mutations. A process
substitution is not a fail-stop boundary. Tests cover four targets and fifteen
invalid inventories; existing staging and locality observer regressions pass.

The repaired resume runner checks the already-installed controller revision,
does not replace it again, and validates all ten retiring agent/installer log
targets before the first agent change. Retiring log streams have no 15-second
request timeout and must end successfully. A bounded post-rollout validation
still needs to establish candidate distribution, traffic, preservation and
cleanup on cl02 before matching Kind. No full Phase 9 or S1–S5 row is verified.

The first resume stops before any agent mutation when a Pod-proxy check targets
the controller's loopback-only HTTP endpoint. It is replaced by the established
owned port-forward observer; the controller and all agents remain Ready. Log
followers are then moved to a separate executable so inherited rollout EXIT/ERR
traps cannot terminate other followers or emit misleading preflight messages.
Local regression checks preserve command stdout/stderr and exit 7, independent
follower lifetime, explicit cancellation/exit 143, and successful completion.
Neither failed observer attempt is reported as feature qualification.
