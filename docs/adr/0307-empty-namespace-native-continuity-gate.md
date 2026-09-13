# ADR 0307: Empty-Namespace Native Continuity Gate

Date: 2026-09-13

Status: qualifier implemented and locally tested; cl02-first live result pending

ADRs 0304–0305 prove bounded Native request/reply and recovery coverage but not
continuity during unrelated Kubernetes changes. Namespace create, relabel and
delete currently advance the global policy revision even when the namespace
has no workloads. Encryption decisions fence exact policy/Service revisions;
independent publication can therefore be a continuity risk. Do not weaken
those packet-path fences or claim attribution without a controlled test.

Add opt-in `UNF_NATIVE_COVERAGE_CONTINUITY=true` to the adopted Native fixture.
After the existing 24 positive and eight unsolicited-negative checks, run a
45-second bounded fresh-connection HTTP observer across eight targets:
same/cross-Node PodIP and translated Service 18080→8080, IPv4/IPv6. Probe failures
are individual observations, never retried away. Require initial positives,
then create/relabel/delete one separately owned empty namespace. Require every
target before, during and after the mutation window, zero failed samples, a
complete observation stream with matching counts, ordered completed mutation
events, exact namespace cleanup, and final fleet convergence. An exec or
observer failure cannot be counted as network evidence or a successful run.

The observer has a bounded per-connection response deadline, a finite runtime,
and a 75-second outer stream deadline. It emits no application bodies or
credentials. Artifacts include per-sample timestamps/latency/outcomes and
before/after controller status. This is a light continuity probe, not a
throughput benchmark, latency SLO or heavy-load qualification. Clock skew can
invalidate cross-host window checks; an incomplete window must fail.

The initial Python-only unit tests passed, but cl02 qualifier `e3337f0` stopped
before any namespace mutations because the immutable test-tools image does not
contain Python. The original 24 allowed/eight denied cases passed first. An
EXIT-trap variable-scope error was also observed; the fixture was removed by
the outer gate. Preserve this as an observer failure, not a continuity result.

Replace the probe with POSIX shell, jq and wget already present in the image,
using the fixture's actual `/health` endpoint. Each connection has a two-second
outer bound and one wget attempt; the parent still rejects every failed sample.
Keep trap variables in the existing subshell rather than function-local scope.
Local tests invoke the actual remote shell with a deterministic wget fixture:
HTTP 200, wrong status, malformed response, timeout and network error; each
sample performs exactly one attempt. Invalid targets and early observer-failure
cleanup are tested too. No test-tools or runtime image change is required.

Commit the repaired qualifier before repeating cl02. Only a complete cl02 pass
permits the same continuity test on Kind. Preserve failed windows and logs.

Qualifier `bf98c0f` repeated the original Native checks successfully, then
stopped before mutations because the image's jq parser rejects `$label` as a
variable name (accepted by host jq 1.8.1). The repaired EXIT cleanup completed
without the earlier scope error; both temporary namespaces were confirmed
absent. Rename that variable and run the entire deterministic shell probe
regression inside the exact test-tools image `e9cce439…2352`: it passes with
network disabled, a read-only root filesystem, no capabilities, a non-root
UID, only the test scripts mounted read-only, and no cluster credentials.
The test harness itself now uses grep available in that image. Host regressions
also pass. No namespace-change/continuity result is claimed for either failed
observer attempt. Repeat cl02 using this image-tested qualifier.
