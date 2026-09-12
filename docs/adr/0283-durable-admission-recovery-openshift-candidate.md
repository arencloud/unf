# ADR 0283: Durable-admission recovery OpenShift candidate

Date: 2026-09-13

Status: cl02 preserved-state deployment and missing-frontier recovery passed; full cl02 gate failed

Runtime `24a66ca946dee9f42b2f4d9fccfe2118838dde73` adds ADR 0281's exact,
authenticated durable-admission recovery to the bounded checkpoint fallback and
timeout responder candidate. The release record and overlay pin its public
controller/agent images by digest. Test tools are unchanged. Kind remains pending
with no invented evidence; qualification order is cl02 first, then fresh Kind.
ADR 0282 independently verifies bounded operations history in both full gates.

Local confirmation passed 728 workspace tests (25 specialized tests excluded),
strict all-target/all-feature workspace lint, the actual five-Node captured
frontier recovery test, and both platform static gates. The release controller
requires only the ordinary C/math/GCC runtime libraries, not dynamic libzstd.

The workstation's Btrfs metadata reservation failed during normal image assembly
after successful compilation. No existing images, user files, or filesystem
layout were removed or changed to bypass it. The same committed Containerfile
was rebuilt with isolated graph, run and image-copy scratch directories on
temporary storage. The existing Rust base was transferred and its image ID
independently matched; Debian was preloaded by its existing digest. Both builds
used `--pull=never` for those bases and the full runtime revision. Only resulting
runtime images, not builder images or operational credentials, were pushed.
Temporary local image storage is ephemeral; public digest pins are durable.

Immediately before this candidate, all five cl02 admission journals still named
generation `1789245125471` with exact predecessor `1789245078215`. This confirms
the admitted-fact selector can supply the missing cut, not merely a prepared
future plan. Each old agent exhausted its 900 fenced startup retries once and
exited with code 1; no OOM was reported. Six unhealthy operators still included
DNS/route timeouts. These are baseline failures, not successful qualification.

Deployment must preserve journals and pinned state, recover the missing frontier,
and prove actual encryption convergence. Pod readiness and configured Native
intent alone do not establish that. Then run the complete Required/selective,
ciphertext, failure, rotation/replacement, persistence, operations and exact
cleanup gate on cl02 before qualifying identical runtime images on Kind.
Phase 9 and stabilization/scale readiness remain unverified until their separate
exit criteria pass.

## cl02 deployment result

Qualifier `31b7d33f1e8063c648db8c91d9f47d33e4f355ae` passed the guarded staged
deployment. Archived deployment evidence SHA-256:
`a1a1b2d706743db8e99f81406cede3948f1bb25797eff0edc74c7509a1b37a6b`.
The controller logged complete authenticated admission recovery, then ordinary
successor publication. All five new agents reached 2/2 Ready with zero restarts.
Independent Node-journal captures showed generation `1789245583383` active on
all five Nodes, no pending generations, empty epoch lists and zero transports.
The saved controller frontier matched; five persistence writes and zero errors
were observed, using ordinary schema-v1 gzip within the existing bound.

This repairs the actual one-generation gap without deleting or rewriting Node
authority. Subsequent pull-synchronized publication began catching up to current
policy/Service revisions. The full gate must still prove current-cut convergence
and all migration/traffic/failure/rotation/replacement/cleanup boundaries.
Six unhealthy operators remained visible after initial Native recovery; neither
complete cluster health nor Phase 9 completion is claimed.

## Full gate failure after deployment

Qualifier `c0f2e67` failed during `explicitly-acknowledged-required-migration`:
the five-Node current-cut wait did not advance beyond `1789252096383` within
360 seconds. Deployment recovery remains verified, but does not qualify this
later migration. The failure trap requested Native intent; it did not prove
Native cleanup. Subsequent public journal captures showed one Node active on
Required generation `1789252472485` (epoch 388), four on older Native generation
`1789252123396`, and differing pending generations. Therefore cleanup is **not
converged**, despite all agents remaining Ready with zero restarts.

Public-only key metadata showed four Nodes had activated epoch 389 while one
still had it Prepared. One active-generation repair reported retired/unknown
epoch 388. The controller's Prepared-only witness-round reconstruction cannot
recover mixed activation phases after restart; this is a reproducible code gap,
not yet a complete causal account of the migration failure. No private key
bytes were captured, and no authority files were deleted or rewritten.

Both platform gates now request an explicit one-hour log window, all matching
lines up to 8 MiB per Pod, and a 60-second collection deadline. Previously the
implicit multi-Pod tail could retain only ten lines. These remain bounded,
potentially truncated diagnostics, not a complete audit log. Full cl02 migration,
recovery and exact cleanup must pass before testing the successor on Kind.
