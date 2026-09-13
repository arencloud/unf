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

Five local tests cover successful and fragmented HTTP status, malformed/closed
responses, connection timeout without retry, unexpected observer errors, and
invalid fixture targets. The Native gate's existing adoption/denial tests pass.
Commit the qualifier before running cl02. Only a complete cl02 pass permits
the same continuity test on Kind. Preserve any failed window and its logs.
