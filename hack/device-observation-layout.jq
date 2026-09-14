# Isolated, little-endian 64-bit kernel diagnostic. Not a production BTF ABI.
def device_kernel_layout($ownership):
  if type!="array" or length!=2 or any(.[]; (.types|type)!="array") then
    error("two BTF type inventories required") else . end
  | . as $inventories
  | [.[].types[]] as $all
  | if ($all|length)>200000 or ($all|length)==0
      or any($all[]; (.id|type)!="number" or .id<=0 or .id!=(.id|floor))
      or ($all|unique_by(.id)|length)!=($all|length)
    then error("invalid or duplicate BTF type coordinates") else . end
  | ($all|map({key:(.id|tostring),value:.})|from_entries) as $types
  | def item($id): $types[$id|tostring] // error("missing BTF type");
    def resolved($id;$depth):
      if $depth>8 then error("BTF alias depth") else
        item($id) | if .kind=="TYPEDEF" or .kind=="CONST" or .kind=="VOLATILE"
          or .kind=="RESTRICT" or .kind=="TYPE_TAG"
          then resolved(.type_id;$depth+1) else . end end;
    def named($name):
      [$inventories[] | [.types[]|select(.kind=="STRUCT" and .name==$name)]]
      | if any(.[];length>1) or (flatten|length)==0 then
          error("missing or ambiguous BTF structure: \($name)")
        else .[][] end;
    def fields($id;$name):
      reduce range(0;64) as $_step
        ({queue:[{id:$id,offset:0,depth:0}],found:[]};
         if (.queue|length)==0 then . else
           .queue[0] as $node | .queue=.queue[1:]
           | resolved($node.id;0) as $type
           | if $node.depth>8 or ($type.kind!="STRUCT" and $type.kind!="UNION")
               or ($type.members|type)!="array" or ($type.members|length)>512
             then error("unsupported BTF member container") else . end
           | reduce $type.members[] as $member (.;
               if $member.name==$name then
                 if ($member.bitfield_size//0)!=0 then error("bitfield member") else
                   .found += [($member|.bits_offset += $node.offset)] end
               elif $member.name=="(anon)" or $member.name=="" then
                 .queue += [{id:$member.type_id,offset:($node.offset+$member.bits_offset),depth:($node.depth+1)}]
               else . end)
           | if (.queue|length)>64 or (.found|length)>1
             then error("BTF member work budget or ambiguity") else . end
         end)
      | if (.queue|length)!=0 then error("BTF member visit budget") else .found end;
    def field($id;$name):
      fields($id;$name) | if length!=1 then error("ambiguous or missing member")
        else .[0] end
      | if (.bits_offset|type)!="number" or .bits_offset<0
        or .bits_offset>524288 or .bits_offset%8!=0
        then error("invalid member offset") else . end;
    def pointer_to($id;$name):
      resolved($id;0) | if .kind!="PTR" then error("expected pointer") else . end
      | resolved(.type_id;0)
      | if .kind!="STRUCT" or .name!=$name then error("wrong pointer target") else . end;
    def integer($id;$size):
      resolved($id;0)
      | if .kind!="INT" or .size!=$size or (.nr_bits//($size*8))!=$size*8
        or (.bits_offset//0)!=0 then error("unexpected integer shape") else . end;
    # Split module BTF may repeat base structures with distinct IDs. Check every
    # combination (at most 2^4, or 2^5 with ownership), never select the first.
    [named("sk_buff") as $skb | named("net_device") as $dev
    | named("net") as $net | named("veth_priv") as $veth
    | field($skb.id;"dev") as $skbdev
    | field($dev.id;"ifindex") as $index
    | field($dev.id;"nd_net") as $ndnet
    | field($ndnet.type_id;"net") as $netptr
    | field($net.id;"net_cookie") as $cookie
    | field($veth.id;"peer") as $peer
    | pointer_to($skbdev.type_id;"net_device") as $_skbdev
    | pointer_to($netptr.type_id;"net") as $_netptr
    | pointer_to($peer.type_id;"net_device") as $_peer
    | integer($index.type_id;4) as $_index
    | integer($cookie.type_id;8) as $_cookie
    | if $skb.size<64 or $skbdev.bits_offset/8>56
        or $skbdev.bits_offset%64!=0 or $dev.size<64 or $dev.size>8192
        or $veth.size<8 or $veth.size>256
        or $peer.bits_offset/8+8>$veth.size or $peer.bits_offset%64!=0
        or $index.bits_offset/8+4>$dev.size
        or ($ndnet.bits_offset+$netptr.bits_offset)/8+8>$dev.size
        or $cookie.bits_offset/8+8>$net.size
        or $cookie.bits_offset/8>65536
      then error("unsupported kernel device layout") else . end
    | {sizes:[$skb.size,$dev.size,$net.size,$veth.size],
       layout:{schemaVersion:1,scope:"isolated-device-readback-layout",wordBytes:8,
       skbDevice:($skbdev.bits_offset/8),deviceIndex:($index.bits_offset/8),
       deviceNet:(($ndnet.bits_offset+$netptr.bits_offset)/8),
       netCookie:($cookie.bits_offset/8),
       devicePeer:((($dev.size+31)/32|floor)*32+$peer.bits_offset/8),
       kernelAdmitted:false}} as $basic
    | if $ownership then
        named("dev_ifalias") as $alias
        | field($dev.id;"flags") as $flags
        | field($dev.id;"ifalias") as $aliasptr
        | pointer_to($aliasptr.type_id;"dev_ifalias") as $_aliasptr
        | field($alias.id;"ifalias") as $data
        | resolved($data.type_id;0) as $array
        | integer($flags.type_id;4) as $_flags
        | if $array.kind!="ARRAY" or $array.nr_elems!=0
            or $flags.bits_offset%32!=0 or $flags.bits_offset/8+4>$dev.size
            or $aliasptr.bits_offset%64!=0 or $aliasptr.bits_offset/8+8>$dev.size
            or $alias.size<8 or $alias.size>256 or $data.bits_offset/8!=$alias.size
          then error("unsupported device ownership layout") else . end
        | integer($array.type_id;1) as $_char
        | $basic | .sizes += [$alias.size]
        | .layout += {schemaVersion:2,scope:"isolated-device-lease-layout",
            deviceFlags:($flags.bits_offset/8),deviceAlias:($aliasptr.bits_offset/8),
            aliasData:($data.bits_offset/8)}
      else $basic end]
    | unique
    | if length!=1 then error("conflicting base/module device layouts")
      else .[0].layout end;

def device_observation_layout: device_kernel_layout(false);
def device_lease_layout: device_kernel_layout(true);
