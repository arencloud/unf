#!/usr/bin/env bash
set -Eeuo pipefail
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jq -n -L "$project_root/hack" '
  include "required-reply-locality";
  {observation:{localAddresses:8,journalSelectedAttachments:2,
    journalSelectedAddresses:4,journalSelectedPayloadBytes:1024}} as $valid
  | {observation:{journalSelectedAttachments:0,journalSelectedAddresses:0,
      journalSelectedPayloadBytes:0}} as $absent
  | [($valid|locality_inventory_valid(4)),
     ($valid|.observation.journalSelectedPayloadBytes=16777216|locality_inventory_valid(4)),
     ($valid|.observation.journalSelectedAddresses=3|locality_inventory_valid(2)),
     ($absent|locality_inventory_absent_valid),
     ($valid|.acquisition="allAdmittedPlans"|locality_all_plan_inventory_valid(4)),
     ($valid|.acquisition="allAdmittedPlans"|locality_all_plan_inventory_valid(0)),
     ($absent|.acquisition="allAdmittedPlans"|locality_all_plan_inventory_valid(0))] as $positive
  | ["journalSelectedAttachments","journalSelectedAddresses","journalSelectedPayloadBytes"] as $fields
  | [ $fields[] as $field | [null,false,true,"4",{},[],-1,0,1.5][] as $bad
      | $valid | .observation[$field]=$bad | locality_inventory_valid(4) ] as $types
  | [ $valid | (.observation.journalSelectedAttachments=5),
       (.observation.journalSelectedAddresses=5), (.observation.localAddresses=3),
       (.observation.journalSelectedPayloadBytes=16777217),
       (.observation.journalSelectedAddresses=2)
      | locality_inventory_valid(4) ] as $bounds
  | [ $fields[] as $field | [null,false,"0",1,-1][] as $bad
      | $absent | .observation[$field]=$bad | locality_inventory_absent_valid ] as $retirement
  | [ ($valid|locality_all_plan_inventory_valid(0)),
      ($absent|.acquisition="allAdmittedPlans"|locality_all_plan_inventory_valid(1)),
      ($valid|.acquisition="requiredOnly"|locality_all_plan_inventory_valid(0)),
      ($fields[] as $field | [null,false,"0",1,-1][] as $bad
       | $absent | .acquisition="allAdmittedPlans" | .observation[$field]=$bad
       | locality_all_plan_inventory_valid(0)) ] as $all_plans
  | ($types+$bounds+$retirement+$all_plans) as $negative
  | if all($positive[]; .==true) and all($negative[]; .==false)
    then {result:"passed",positiveCases:($positive|length),negativeCases:($negative|length)}
    else error("journal inventory observer accepted invalid counters") end
'
