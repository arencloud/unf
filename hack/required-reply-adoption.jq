def reply_generation_cut_valid($mode; $source; $destination; $count; $policy; $service; $egress):
  $count>0 and length==$count and ([.[].node]|unique|length)==$count
  and ([.[].generation]|unique|length)==1
  and all(.[];.pending==false and .generation>0 and .policyRevision==$policy
    and .serviceRevision==$service and .egressRevision==$egress
    and (if $mode=="native" then (.epochs|length)==0
         elif $mode=="required" then
           if .node==$source or .node==$destination then (.epochs|length)>0 and all(.epochs[];.>0)
           else (.epochs|length)==0 end
         else false end))
  and any(.[];.node==$source) and any(.[];.node==$destination);

def reply_provenance_valid($source; $destination; $source_node; $destination_node; $policy; $generation):
  .snapshot.policyRevision==$policy and .snapshot.generation==$generation
  and .snapshot.recipient.nodeName==$destination_node
  and any(.snapshot.epochs[];.contract.schemaVersion==2 and any(.contract.plans[];
    .source.identity==$destination and .destination.identity==$source
    and .source.node.name==$destination_node and .destination.node.name==$source_node
    and .disposition=="required"
    and .policy.replyTo=={source:$source,destination:$destination} and .policy.revision==$policy));
