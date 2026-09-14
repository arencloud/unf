include "device-lease-concurrency-gate";

# bpftool -j writes failures to JSON stdout, not the human stderr channel.
# Only the exact requested ID's ENOENT is evidence of retirement.
def device_lease_retired_map($id):
  ($id|natural and .>0 and .<=4294967295)
  and .=={error:"get map by id (\($id)): No such file or directory"};

def bank_ledger($tag; $outcome):
  .schemaVersion==1 and .capacity==65536 and .productionAuthority==false
  and (.entries|type)=="array" and (.entries|length)<=40000
  and all(.entries[];type=="array" and length==3 and (.[0]|natural and .<40000)
      and .[1]==$tag and .[2]==$outcome)
  and ([.entries[][0]]|sort|unique)==[.entries[][0]];

def device_lease_publication_gate:
  require(.traffic|traffic(20000); "invalid publication observers")
  | require(.traffic.foreign4.received==0 and .traffic.foreign6.received==0
      and .traffic.original4.received>100 and .traffic.original6.received>100; "publication delivery boundary failed")
  | require((.before|type)=="array" and (.before|length)==3 and all(.before[];natural)
      and .before[0]==40040 and .before[1]+.before[2]==40040; "invalid prior counters")
  | require((.afterB|type)=="array" and (.afterB|length)==3 and all(.afterB[];natural)
      and .dispatch==[40040,0,40]; "dispatcher or B accounting failed")
  | require((.ledgerA|bank_ledger(1;1)) and (.ledgerB|bank_ledger(2;2)); "invalid generation sequence ledger")
  | (.traffic.counters[0]-.before[0]) as $a
  | .afterB[0] as $b
  | require($a>100 and $b>100 and $a+$b==40000
      and .traffic.counters[1]-.before[1]==$a and .traffic.counters[2]==.before[2]
      and .afterB==[$b,0,$b]; "generation counter mismatch")
  | require((.ledgerA.entries|length)==$a and (.ledgerB.entries|length)==$b
      and ([.ledgerA.entries[][0],.ledgerB.entries[][0]]|sort)==[range(0;40000)]; "missing or multiply attributed sequence")
  | ([.traffic.original4.sequences[]|.*2]+[.traffic.original6.sequences[]|.*2+1]|sort) as $delivered
  | require($delivered==[.ledgerA.entries[][0]]; "delivery does not match the allow generation ledger")
  | {schemaVersion:1,scope:"isolated-whole-program-generation-publication",sent:40000,
      allowGenerationDeliveries:$a,denyGenerationRejections:$b,foreignDeliveries:0,
      receiverSocketDrops:0,unobservedRedirects:0,exactSequenceAttribution:true,
      emptyDispatcherDenials:40,productionAuthority:false,productionPublicationVerified:false};
