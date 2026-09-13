#!/usr/bin/env bash
set -Eeuo pipefail
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jq -n -L "$project_root/hack" '
  include "phase9-rollout-guard";
  {items:[{metadata:{name:"agent-a",uid:"uid-a"},spec:{nodeName:"worker-a",
      containers:[{name:"agent"},{name:"installer"}],initContainers:[{name:"init"}]}},
    {metadata:{name:"controller",uid:"uid-c"},spec:{nodeName:"worker-b",containers:[{name:"controller"}]}}]} as $valid
  | ($valid|phase9_log_targets) as $targets
  | [null,{}, {items:[]},
      ($valid|.items=null),($valid|.items[0].metadata.name=null),
      ($valid|.items[0].metadata.uid=""),($valid|.items[0].spec.nodeName=null),
      ($valid|.items[0].spec.containers=[]),($valid|.items[0].spec.containers=null),
      ($valid|.items[0].spec.containers[0].name=null),($valid|.items[0].spec.containers[0].name=""),
      ($valid|.items[0].spec.initContainers={}),($valid|.items[0].spec.initContainers[0].name=null),
      ($valid|.items[0].spec.initContainers[0].name="agent"),
      ($valid|.items += [.items[0]])] as $invalid
  | if ($targets|length)==4 and ($targets|map(select(.kind=="init"))|length)==1
      and ($targets|map(select(.pod=="controller" and .container=="controller" and .node=="worker-b"))|length)==1
      and all($invalid[]; try (phase9_log_targets|false) catch true)
    then {result:"passed",targets:4,negativeCases:($invalid|length)}
    else error("log target materialization failed its atomic inventory checks") end
'
# Failure must be checked in the foreground before any mutation or loop starts;
# do not hide materialization in a process substitution whose exit is ignored.
if jq -n -L "$project_root/hack" 'include "phase9-rollout-guard"; {items:[]}|phase9_log_targets' >/dev/null 2>&1; then
    exit 1
fi
