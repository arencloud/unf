#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jq -L "$root/hack" -en '
  include "native-transport-adoption";
  def require($condition): if $condition then . else error("Native adoption invariant failed") end;
  {policy_revision:7,dataplane_enforcement:true,source:{identity:11},destination:{identity:21},
   decision:{verdict:"Allow",policy_id:9},direction:"Ingress",ip_family:"ipv4"} as $explain
  | require($explain | native_policy_observed("Allow";"Ingress";"ipv4"))
  | require($explain | .decision.policy_id=null | native_policy_observed("Allow";"Ingress";"ipv4") | not)
  | require($explain | .source.identity=0 | native_policy_observed("Allow";"Ingress";"ipv4") | not)
  | require($explain | .source.identity="11" | native_policy_observed("Allow";"Ingress";"ipv4") | not)
  | require($explain | native_policy_observed("Deny";"Ingress";"ipv4") | not)
  | require($explain | native_policy_observed("Allow";"Egress";"ipv4") | not)
  | require($explain | native_policy_observed("Allow";"Ingress";"ipv6") | not)
  | {source_epoch:30,identity_revision:4} as $topology
  | {all_converged:true,expected_agents:1,reporting_agents:1,nodes:[{fresh:true,converged:true,
      report:{ready:true,bpf_loaded:true,applied_policy_revision:7,applied_policy_epoch:30,
        applied_identity_epoch:30,applied_identity_revision:4}}]} as $agents
  | require($agents | native_agent_cut_applied(7;$topology))
  | require($agents | native_agent_cut_applied(8;$topology) | not)
  | require($agents | .nodes[0].report.applied_policy_epoch=29 | native_agent_cut_applied(7;$topology) | not)
  | require($agents | .nodes[0].report.applied_identity_revision=3 | native_agent_cut_applied(7;$topology) | not)
  | require($agents | .nodes=[] | native_agent_cut_applied(7;$topology) | not)
  | require($agents | .nodes[0].fresh=false | native_agent_cut_applied(7;$topology) | not)
  | require($agents | .nodes[0].fresh="false" | native_agent_cut_applied(7;$topology) | not)
  | [range(0;3) | {kind:"Pod",metadata:{name:("pod-"+tostring)},spec:{nodeName:"worker-a"},
      status:{podIPs:[{ip:("10.0.0."+(.+1|tostring))},{ip:("fd00::"+(.+1|tostring))}]}}] as $pods
  | [range(0;2) | {kind:"Service",metadata:{name:("service-"+tostring)},
      spec:{clusterIPs:[("10.1.0."+(.+1|tostring)),("fd01::"+(.+1|tostring))]}}] as $services
  | {items:($pods+$services)} as $fixture
  | ($topology + {workloads:[$pods[] | {namespace:"fixture",name:.metadata.name,identity_id:11,
      node_name:.spec.nodeName,ipv4_addresses:[.status.podIPs[0].ip],ipv6_addresses:[.status.podIPs[1].ip]}],
      services:[$services[] | {namespace:"fixture",name:.metadata.name,cluster_ips:.spec.clusterIPs,
        backends:[{ready:true,addresses:["10.0.0.1"]}]}]}) as $observed
  | require($observed | native_fixture_observed("fixture";$fixture))
  | require($observed | .workloads[0].identity_id=0 | native_fixture_observed("fixture";$fixture) | not)
  | require($observed | .workloads[0].ipv6_addresses=["fd00::99"] | native_fixture_observed("fixture";$fixture) | not)
  | require($observed | .workloads[0].node_name="worker-b" | native_fixture_observed("fixture";$fixture) | not)
  | require($observed | .services[0].cluster_ips=["10.1.0.99"] | native_fixture_observed("fixture";$fixture) | not)
  | require($observed | .services[0].backends=[] | native_fixture_observed("fixture";$fixture) | not)
  | require($observed | .workloads=[] | native_fixture_observed("fixture";$fixture) | not)
  | true' >/dev/null
echo 'Native fixture adoption rejects stale epochs, missing identities, unknown policy and unobserved Services'
