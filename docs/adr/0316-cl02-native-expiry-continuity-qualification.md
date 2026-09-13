# ADR 0316: cl02 Native Expiry and Continuity Qualification

Date: 2026-09-13

Status: cl02 bounded Native/churn gate passed; matching Kind and broader Phase 9 pending

## Runtime and deployment

Runtime `5ea1bd2b759915edae0fe674863c5b3e9ebefb24`, qualifier
`bb191aba045a335d710f1a3689bee3b2e642c6ae`, uses ADR 0314's verified object
and immutable controller/agent manifests. The guarded cl02 `cl02-st7gq`
deployment passes exact runtime/schema checks, RHCOS/SELinux host contracts,
all five agent transitions and convergence, and absence of kube-proxy. No
map/journal/frontier reset, Node reboot or liveness relaxation was used.

Three agents waited for the exact startup fleet barrier before becoming Ready;
this is observed admission delay, not instantaneous update performance. One
separate management Pod-list read timed out and a later read succeeded. It is
not counted as a dataplane traffic result. Background image archiving finished
before the traffic gate.

## Traffic and cleanup

The adoption-fenced fixture passes 24 allowed TCP/UDP request/reply cases and
eight independently initiated reverse denials across IPv4/IPv6, same/cross-Node,
PodIP, Service and translated Service ports. Workers are `.202` and `.204`.

Continuous fresh HTTP probing spans empty Namespace create, relabel and delete:
232 samples, zero failures, 29 samples on each of eight local/remote,
Pod/translated-Service, IPv4/IPv6 paths. Every path appears before, during and
after churn. Policy revision stays 450; four invalidations are skipped. The
probe completes normally without retries masking a failure. Both owned test
Namespaces are positively absent and all five agents converge after cleanup.

This qualifies the expired-tuple repair plus the empty-Namespace no-op slice.
It does not establish arbitrary policy/Service update atomicity, active tuple
collision handling, LRU capacity behavior, sustained-load resource savings,
Required locality/replica/reply coverage or full Phase 9 lifecycle closure.

## Logs and evidence

All six UNF Pods remain Ready with zero restarts. Current/container log review
finds no ERROR, panic, OOM, verifier rejection or stopped-dataplane entries.
Retained warnings include existing clsact (255), flow/topology retention
(159/36), fresh peer testimony (42), startup admission (16), one deferred key
catch-up, the known large IPv4 ipBlock/two named-port conflicts, and one failed
native EgressReachabilityPlan list. These remain S1 attribution/noise findings;
neither the log review nor this traffic pass declares overall cluster health.

Ignored evidence is under `.artifacts/s1-verifier-5ea1bd2-*`.

| Record | SHA-256 |
|---|---|
| Deployment JSON | `37d6ed59d299af2fbfc12b52519c4341e90ed4f648783d79237c293ecae9a309` |
| Native evidence JSON | `c6c10fde112fb61d941a780d5b487f3a5111728570837118122c75c344d3dcc4` |
| Continuity summary | `8857ea9fc3b4e008998652c7358883ae98f7cf2a5d3645be86425172ce5f658d` |
| Fresh-connection records | `faa10edfce20d12134adf27a8b6718723dcabc4511d0f8aabadbb88d65185462` |

Commit and push this checkpoint before importing the exact archived manifests
into retained Kind. Preserve the prior failed candidates and Kind's state.
