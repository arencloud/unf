# ADR 0350: Locality Distribution Platform Gate

Date: 2026-09-14

Status: qualifier verified locally; platform execution pending

The existing selective Required reply qualifier gains the explicit opt-in
`UNF_REQUIRED_REPLY_REQUIRE_LOCALITY_CANDIDATE=true`. Older runtime gates retain
their prior result shape and behavior when the option is absent.

The new read-only observer requires candidate absence at the Native baseline,
then a replayed candidate on each participating worker after Required admission.
It joins the observed cluster and Node UID to current Kubernetes metadata,
membership and plan digest to the public durable plan, and identity/routing
coordinates to fresh converged agent reports. Source/destination address counts
must cover at least their dual-stack fixture workloads. Kernel admission and
observed-delivery flags must remain false. Native cleanup must remove candidates
on both workers with a positive observation timestamp.

Observations use the Kubernetes API Pod proxy, avoiding extra observer Pods,
agent restarts, token extraction or traffic-producing certificate probes. Failed
HTTP/API reads remain failures, not absence. Each retry preserves its status,
plan and agent-report cut. The existing traffic, ciphertext, CNI ownership and
normal retirement gates remain independent and mandatory when selected.

Local validation passes shell syntax and two positive / 105 negative JSON gate
cases, including missing context/report/plan coordinates and false admission
claims. cl02 API proxy reachability is checked against the unchanged `450de80`
agent's version endpoint; this does not qualify the new feature. Candidate
runtime source is `f984db9e8b041c014814958054a1908e9829233c`, with unchanged BPF.
Build contexts now exclude all qualification artifacts except that exact BPF
input. No credentials enter the build recipe or tracked evidence.

The candidate image must qualify on cl02 before matching retained Kind. This
gate proves bounded authenticated placement distribution/status only, not the
still-unimplemented local Required packet consumer or full L3/L4/L5/Q/S1–S5.
