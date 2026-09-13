#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jq -en -L "$root/hack" '
  include "local-delivery-device-gate";
  def snapshot($index; $device; $packets; $overlimits; $bind):
    [{"total acts":0},{actions:[{kind:"mirred",mirred_action:"redirect",direction:"egress",
      control_action:{type:"stolen"},index:$index,to_dev:$device,
      stats:{packets:$packets,overlimits:$overlimits,bytes:($packets*50)},
      bind:$bind,ref:($bind+1),not_in_hw:true}]}];
  [snapshot(101;"target";2;0;2),snapshot(101;"renamed";4;0;2),
   snapshot(101;"renamed";6;2;2),snapshot(101;"*";8;2;2),
   snapshot(101;"*";10;4;2),snapshot(102;"target";0;0;0),
   snapshot(102;"target";2;0;2),snapshot(101;"*";10;4;0)] as $good |
  ($good | device_lifetime_verified) and
  ([range(0;8) as $stage | range(0;12) as $mutation |
    ($good |
      if $mutation == 0 then .[$stage][1].actions[0].kind="other"
      elif $mutation == 1 then .[$stage][1].actions[0].index+=1
      elif $mutation == 2 then .[$stage][1].actions[0].to_dev="foreign"
      elif $mutation == 3 then .[$stage][1].actions[0].stats.packets+=1
      elif $mutation == 4 then .[$stage][1].actions[0].stats.overlimits+=1
      elif $mutation == 5 then del(.[$stage][1].actions[0].stats.bytes)
      elif $mutation == 6 then .[$stage][1].actions[0].bind+=1
      elif $mutation == 7 then .[$stage][1].actions[0].not_in_hw=false
      elif $mutation == 8 then .[$stage][1].actions+=.[$stage][1].actions
      elif $mutation == 9 then .[$stage][1].actions[0].direction="ingress"
      elif $mutation == 10 then .[$stage][1].actions[0].mirred_action="mirror"
      else .[$stage][1].actions[0].control_action.type="pipe" end
      | device_lifetime_verified)] | all(.==false)) and
  ([null,{},[],[$good[0]],($good + [$good[0]]),($good|reverse)] |
     all(.[]; device_lifetime_verified == false))' >/dev/null
echo 'Device lifetime evidence gate: positive, 96 field mutations and six malformed/reordered cuts passed'
