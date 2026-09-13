def native_positive_integer: type == "number" and floor == . and . > 0;

def native_fixture_observed($namespace; $fixture):
  . as $topology
  | [$fixture.items[] | select(.kind == "Pod")] as $pods
  | [$fixture.items[] | select(.kind == "Service")] as $services
  | ($pods | length) == 3 and ($services | length) == 2
  and (.source_epoch | native_positive_integer) and (.identity_revision | native_positive_integer)
  and all($pods[]; . as $pod
    | any($topology.workloads[];
        .namespace == $namespace and .name == $pod.metadata.name
        and (.identity_id | native_positive_integer) and .node_name == $pod.spec.nodeName
        and ((.ipv4_addresses + .ipv6_addresses | sort)
             == ([$pod.status.podIPs[].ip] | sort))))
  and all($services[]; . as $service
    | any($topology.services[];
        .namespace == $namespace and .name == $service.metadata.name
        and (.cluster_ips | sort) == ($service.spec.clusterIPs | sort)
        and any(.backends[]; .ready == true and (.addresses | length) > 0)));

def native_policy_observed($verdict; $direction; $family):
  (.policy_revision | native_positive_integer) and .dataplane_enforcement == true
  and (.source.identity | native_positive_integer) and (.destination.identity | native_positive_integer)
  and .decision.verdict == $verdict and (.decision.policy_id | native_positive_integer)
  and .direction == $direction and .ip_family == $family;

def native_agent_cut_applied($policy; $topology):
  .all_converged == true and (.expected_agents | native_positive_integer)
  and .reporting_agents == .expected_agents
  and (.nodes | length) == .expected_agents
  and all(.nodes[];
    .fresh == true and .converged == true and .report.ready == true and .report.bpf_loaded == true
    and .report.applied_policy_revision == $policy
    and .report.applied_policy_epoch == $topology.source_epoch
    and .report.applied_identity_epoch == $topology.source_epoch
    and (.report.applied_identity_revision | native_positive_integer)
    and .report.applied_identity_revision >= $topology.identity_revision);
