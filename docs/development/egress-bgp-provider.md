# Egress BGP provider

Phase 8.8d is an opt-in node-local GoBGP provider for an `EgressPolicy` whose
reachability provider name is `bgp`. The provider is disabled unless the agent
receives `--egress-bgp-config-path`; native/static compatibility behavior is not
silently changed.

## Build and verify

```console
make egress-bgp-image
hack/verify-egress-bgp.sh
```

The focused gate starts two gateway speakers and two external fabric speakers
on an isolated dual-stack network. `make egress-bgp-test` additionally inherits
the prior Phase 8 safety gates and runs all strict domain, controller, agent, and
adapter checks.

## Node-local policy

The configuration is canonical JSON. Its `instance` must exactly equal the
provider instance selected by the egress intent. A peer address identifies the
BGP transport session; its `families` may negotiate both IPv4 and IPv6 over that
session. `permittedExportPrefixes` is a mandatory default-deny envelope, not a
request to originate those prefixes.

Start from a document like this, with an all-zero placeholder digest:

```json
{
  "schemaVersion": 1,
  "algorithm": "causal-constrained-convergence-v1",
  "revision": 1,
  "instance": "fabric-a",
  "localAsn": 64512,
  "routerId": "192.0.2.10",
  "ipv4NextHop": "198.51.100.10",
  "ipv6NextHop": "2001:db8:100::10",
  "peers": [
    {
      "name": "tor-a",
      "address": "198.51.100.1",
      "remoteAsn": 64513,
      "failureDomain": "rack-a",
      "families": ["Ipv4", "Ipv6"],
      "multihopTtl": 1,
      "maximumReceivedPrefixes": 1024,
      "bfd": {
        "port": 3784,
        "desiredMinimumTxIntervalMicroseconds": 300000,
        "requiredMinimumReceiveIntervalMicroseconds": 300000,
        "detectionMultiplier": 3
      }
    },
    {
      "name": "tor-b",
      "address": "198.51.100.2",
      "remoteAsn": 64514,
      "failureDomain": "rack-b",
      "families": ["Ipv4", "Ipv6"],
      "multihopTtl": 1,
      "maximumReceivedPrefixes": 1024,
      "bfd": {
        "port": 3784,
        "desiredMinimumTxIntervalMicroseconds": 300000,
        "requiredMinimumReceiveIntervalMicroseconds": 300000,
        "detectionMultiplier": 3
      }
    }
  ],
  "permittedExportPrefixes": [
    {"address": "192.0.2.0", "length": 24},
    {"address": "2001:db8:200::", "length": 64}
  ],
  "maximumChangedPrefixes": 64,
  "maximumTotalPrefixes": 1024,
  "maximumPathsPerPrefix": 4,
  "gracefulRestart": {"restartSeconds": 30, "stalePathSeconds": 90},
  "digest": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}
```

Seal it before installation:

```console
cargo run --quiet -p unf-gobgp --example seal_config \
  < egress-bgp.unsealed.json > egress-bgp.json
```

On each Node, mount the sealed file and durable-state directory into the agent,
run `gobgpd --api-hosts=127.0.0.1:50051` in the same host network namespace, and
set:

```text
--egress-bgp-config-path=/etc/unf/egress-bgp.json
--egress-bgp-endpoint=http://127.0.0.1:50051
--egress-bgp-state-path=/var/lib/unf/cni/v1/egress-bgp.json
```

The state file must remain private and writable by the agent. The controller
delivers only exact lease-bound plans containing that authenticated Node; the
agent exports only admitted local gateway addresses inside the configured
prefix envelope. Same-revision synchronization still checks the live daemon and
reconstructs missing RIB state from the complete durable snapshot.

## Security and current boundary

Single-hop sessions use GTSM, peer drift is rejected, and UNF owns only peers
whose description starts with `unf/egress-bgp/`. The current schema does not
transport TCP-AO or TCP-MD5 secrets. Use a protected routing segment and do not
claim cryptographically authenticated BGP until a dedicated secret-delivery
milestone lands.

BFD is optional per peer because unilateral activation breaks a valid session.
When configured it is restricted to IPv4 single-hop UDP 3784, bounded 100 ms–10 s
intervals, and multiplier 2–50. Use conservative production timers. GoBGP's
current native implementation has no BFD authentication, echo, or demand mode.
The agent publishes exact digest-sealed state through its authenticated Node-UID
channel; the default Causal Failure Lattice treats it only as fast liveness,
collapses shared causal dependencies, and requires an independent route or
dataplane plane before recommending path suppression. It never authorizes
ownership or promotion. One BFD transport can protect both negotiated route
families. IPv6 BFD transport is rejected because its GoBGP v4.9 live fixture did
not establish; EVPN, scale qualification, full Kind platform
qualification, and OpenShift qualification remain separate tracked work.

The route transaction, Causal Route Capsule, evidence, rollback, and recovery
rationale is in [ADR 0151](../adr/0151-causal-constrained-bgp-convergence.md).
The BFD authority boundary and Causal Failure Lattice are in
[ADR 0152](../adr/0152-causal-failure-lattice.md).
