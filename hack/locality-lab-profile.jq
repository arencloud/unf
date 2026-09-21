def locality_lab_capabilities: ["BPF", "NET_ADMIN", "PERFMON", "SYS_ADMIN"];
def locality_lab_context:
  {privileged:false,allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,
   runAsUser:0,runAsGroup:0,seLinuxOptions:{type:"spc_t"},
   seccompProfile:{type:"RuntimeDefault"},
   capabilities:{drop:["ALL"],add:locality_lab_capabilities}};
def locality_lab_context_valid:
  .privileged==false and .allowPrivilegeEscalation==false
  and .readOnlyRootFilesystem==true and .runAsUser==0 and .runAsGroup==0
  and .seLinuxOptions.type=="spc_t" and .seccompProfile=={type:"RuntimeDefault"}
  and .capabilities.drop==["ALL"]
  and (.capabilities.add|sort)==(locality_lab_capabilities|sort);
def locality_lab_pod($check):
  .spec.containers[0].securityContext=locality_lab_context
  | .spec.containers[0].volumeMounts=[{name:"tmp",mountPath:"/tmp"},{name:"run",mountPath:"/run"}]
  | .spec.volumes=[{name:"tmp",emptyDir:{sizeLimit:"128Mi"}},{name:"run",emptyDir:{sizeLimit:"16Mi"}}]
  | .spec.containers[0].command=(["bash","-ec",$check,"locality-lab-profile"]+.spec.containers[0].command);
def locality_lab_pod_valid:
  .spec.automountServiceAccountToken==false and .spec.restartPolicy=="Never"
  and (.spec.containers|length)==1
  and (.spec.containers[0].securityContext|locality_lab_context_valid)
  and .spec.containers[0].volumeMounts==[{name:"tmp",mountPath:"/tmp"},{name:"run",mountPath:"/run"}]
  and (.spec.volumes|map({name,emptyDir}))==[{name:"tmp",emptyDir:{sizeLimit:"128Mi"}},{name:"run",emptyDir:{sizeLimit:"16Mi"}}]
  and all(.spec.volumes[];keys|sort==["emptyDir","name"]);
