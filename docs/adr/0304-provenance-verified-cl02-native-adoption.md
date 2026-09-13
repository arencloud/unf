# ADR 0304: Provenance-Verified cl02 Native Adoption

Date: 2026-09-13

Status: expanded cl02 Native gate passed; retained Kind recovery next

Runtime `54f55112e37bb91c35e46683b4bf32533bd4294d`, qualifier
`2c97a8f156c207c450b8978b8a3ee41bec78885c`, uses ADR 0303's immutable images.
The corrected controller-first/node-serial deployment passed exact versions,
current schemas, host checks and five-agent convergence with kube-proxy absent.
All six runtime Pods had zero restarts in the post-replacement observation.

The strengthened Native gate then passed on cl02, before any retained Kind
upgrade. The observer matched all three fixture workloads and both dual-stack
Services, then all 32 explanation decisions at policy revision 517 with all
five agents applying the matching controller epoch and revision. It verified
24 allowed request/stateful-return cases and eight independently observed
unsolicited reverse denials: same/cross-worker Pod IPs and Services, IPv4/IPv6,
TCP/UDP, including Service 18080→8080 and 53→5353. Fixture namespace absence
and five-agent convergence after cleanup passed. This was a single bounded
run, not an uninterrupted churn/soak or load-capacity result.

| Ignored local evidence | SHA-256 |
|---|---|
| `s1-provenance-54f5511-cl02-deploy.json` | `88f353ef40cd49c360e5eac908936f8a6ac8301ec712c17dcd85f46fcbeb0041` |
| `s1-provenance-54f5511-native-cl02/evidence.json` | `6f22710cc44c06c33ad9ae69f553b970d099c0306fbf6062e8fb3eb3b1f22972` |

ADRs 0299 and 0302 retain the earlier packet and provenance failures. The
operator snapshot during this run showed Insights and network unhealthy; it
does not establish sustained recovery of the other operators.

Next update only the retained Kind controller first, keeping old agents and
their public journals intact, to test actual mixed-cursor receipt recovery.
Then replace agents serially and repeat the same Native gate. Keep full Phase 9
Kind qualification pending until its complete lifecycle gate passes; Native
coverage alone cannot qualify Required encryption, ciphertext, rotation,
replica/reply behavior, continuity, or S1–S5 heavy-load stabilization.
