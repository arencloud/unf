#!/usr/bin/env bash
set -Eeuo pipefail
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jq -n -L "$project_root/hack" -e '
  include "service-shutdown-gate";
  def completed: {metadata:{uid:"owned"},spec:{hostPID:false,hostNetwork:false},
    status:{phase:"Succeeded",containerStatuses:[{restartCount:0,
      state:{terminated:{exitCode:0,reason:"Completed"}}}]}};
  if (completed | shutdown_fixture_succeeded("owned") | not) then error("valid shutdown rejected") else . end |
  [(completed | .status.phase="Running"),
   (completed | .status.phase="Pending")] | . as $pending |
  if any($pending[]; shutdown_fixture_terminal("owned")) then error("nonterminal phase admitted") else . end |
  [(completed | .metadata.uid="foreign"),
   (completed | .status.phase="Failed"),
   (completed | .status.containerStatuses[0].restartCount=1),
   (completed | .status.containerStatuses[0].state.terminated.exitCode=137),
   (completed | .status.containerStatuses[0].state.terminated.reason="Error"),
   (completed | .status.containerStatuses[0].state={running:{}}),
   (completed | .status.containerStatuses=[]),
   (completed | .status.containerStatuses += .status.containerStatuses),
   (completed | .spec.hostPID=true),
   (completed | .spec.hostNetwork=true)] | . as $invalid |
  if any($invalid[]; shutdown_fixture_succeeded("owned")) then error("invalid shutdown admitted") else . end |
  if (completed | .status.phase="Failed" | shutdown_fixture_terminal("owned") | not)
    then error("failed terminal state must be observable") else . end |
  "Shutdown observer: positive exit, phase lag, failed exit and ten negative cases passed"
'
