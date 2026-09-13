# Exact isolated-fixture action evidence, not general tc JSON acceptance.
def device_action:
  if type != "array" then error("not an action dump") else
    [.[] | .actions? // empty | .[]] |
    if length != 1 then error("ambiguous action dump") else .[0] end
  end;

def device_action_matches($index; $device; $packets; $overlimits; $bindings):
  .kind == "mirred" and .mirred_action == "redirect" and .direction == "egress"
  and .control_action.type == "stolen" and .index == $index and .to_dev == $device
  and .stats.packets == $packets and .stats.overlimits == $overlimits
  and (.stats.bytes | type == "number" and . >= 0 and floor == .)
  and (if $packets > 0 then .stats.bytes > 0 else .stats.bytes == 0 end)
  and .bind == $bindings and .ref == ($bindings + 1)
  and .skip_hw == true and .skip_sw != true and .in_hw != true;

def device_lifetime_verified:
  try (
    type == "array" and length == 8 and
    (map(device_action) |
      (.[0] | device_action_matches(101; "target"; 2; 0; 2)) and
      (.[1] | device_action_matches(101; "renamed"; 4; 0; 2)) and
      (.[2] | device_action_matches(101; "renamed"; 6; 2; 2)) and
      (.[3] | device_action_matches(101; "*"; 8; 2; 2)) and
      (.[4] | device_action_matches(101; "*"; 10; 4; 2)) and
      (.[5] | device_action_matches(102; "target"; 0; 0; 0)) and
      (.[6] | device_action_matches(102; "target"; 2; 0; 2)) and
      (.[7] | device_action_matches(101; "*"; 10; 4; 0)))
  ) catch false;
