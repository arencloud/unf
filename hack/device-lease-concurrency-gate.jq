def require($condition; $message):
  if $condition then . else error($message) end;

def natural: type=="number" and .>=0 and .==floor and .<=1000000;

def device_lease_counters:
  require((.values|type)=="array" and (.values|length)>0 and (.values|length)<=8192; "invalid per-CPU counter inventory")
  | require(([.values[].cpu]|all(.[];natural)) and ([.values[].cpu]|unique|length)==(.values|length); "duplicate or invalid CPU")
  | [.values[]
      | require((.value|type)=="array" and (.value|length)==24 and all(.value[];type=="string" and test("^0x[0-9a-fA-F]{2}$")); "invalid counter bytes")
      | [.value[]|ltrimstr("0x")|ascii_downcase|explode|reduce .[] as $digit (0; . * 16 + ("0123456789abcdef"|index([$digit]|implode)))]
      | [range(0;24;8) as $offset
          | require(all(.[$offset+4:$offset+8][];.==0); "counter exceeds fixture bound")
          | .[$offset] + .[$offset+1]*256 + .[$offset+2]*65536 + .[$offset+3]*16777216]]
  | [range(0;3) as $column|[.[][$column]]|add]
  | require(all(.[];natural); "counter sum exceeds fixture bound");

def sender($family; $count):
  .schemaVersion==1 and .role=="sender" and .family==$family
  and .sent==$count and .productionAuthority==false
  and (.elapsedNanos|type)=="number" and .elapsedNanos>0 and .elapsedNanos<=25000000000;

def receiver($family; $count):
  .schemaVersion==1 and .role=="receiver" and .family==$family
  and .productionAuthority==false and .socketDrops==0 and .queuedBytes==0
  and (.received|natural) and (.sequences|type)=="array"
  and (.sequences|length)==.received and (.sequences|sort|unique)==.sequences
  and all(.sequences[];natural and .<$count);

def traffic($count):
  (.sent4|sender(4;$count)) and (.sent6|sender(6;$count))
  and (.original4|receiver(4;$count)) and (.original6|receiver(6;$count))
  and (.foreign4|receiver(4;$count)) and (.foreign6|receiver(6;$count))
  and (.counters|type)=="array" and (.counters|length)==3 and all(.counters[];natural)
  and (.sent4.runToken|type)=="array" and (.sent4.runToken|length)==16
  and all(.sent4.runToken[];natural and .<=255) and any(.sent4.runToken[];.!=0)
  and .sent4.runToken==.sent6.runToken and .sent4.runToken==.original4.runToken
  and .sent4.runToken==.original6.runToken and .sent4.runToken==.foreign4.runToken
  and .sent4.runToken==.foreign6.runToken;

def device_lease_concurrency_gate:
  require(.control|traffic(20); "invalid control observations")
  | require(.control.original4.received==0 and .control.original6.received==0
      and .control.foreign4.received==20 and .control.foreign6.received==20
      and .control.counters==[40,40,0]; "foreign positive control failed")
  | require(.stress|traffic(20000); "invalid stress observations")
  | require(.control.sent4.runToken!=.stress.sent4.runToken; "reused control/stress token")
  | require(.stress.foreign4.received==0 and .stress.foreign6.received==0; "foreign delivery during movement")
  | require(.stress.original4.received>100 and .stress.original6.received>100; "missing original-namespace delivery")
  | (.stress.counters[1]-40) as $redirects
  | .stress.counters[2] as $rejections
  | (.stress.original4.received+.stress.original6.received) as $received
  | require(.stress.counters[0]==40040 and $redirects>100 and $rejections>100
      and $redirects+$rejections==40000 and $received<=$redirects; "attempt accounting mismatch")
  | {schemaVersion:1,scope:"isolated-concurrent-target-peer-movement",sent:40000,
      originalDeliveries:$received,foreignDeliveries:0,requestedRedirects:$redirects,
      classifierRejections:$rejections,unobservedRedirects:($redirects-$received),
      receiverSocketDrops:0,foreignPositiveControls:40,productionAuthority:false,
      losslessHandoffVerified:false,concurrentLifetimeVerified:false};
