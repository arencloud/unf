# Management readiness is intentionally not required before fleet admission.
# A candidate that has restarted or terminated is not healthy staging, however.
def phase9_log_targets:
  if (.items | type) != "array" or (.items | length) == 0 then
    error("log observation requires a nonempty Pod inventory")
  elif any(.items[];
    ([.metadata.name,.metadata.uid,.spec.nodeName] | any(.[]; type != "string" or length == 0))
    or (.spec.containers | type) != "array" or (.spec.containers | length) == 0
    or ((.spec.initContainers // []) | type) != "array"
    or ([.spec.containers[], (.spec.initContainers // [])[]] | any(.[]; (.name | type) != "string" or (.name | length) == 0))) then
    error("log observation has incomplete Pod/container coordinates")
  else
    [.items[] as $pod
      | ($pod.spec.containers[] | {name:.name,kind:"container"}),
        (($pod.spec.initContainers // [])[] | {name:.name,kind:"init"})
      | {pod:$pod.metadata.name,podUid:$pod.metadata.uid,node:$pod.spec.nodeName,container:.name,kind}]
    | if length != (unique_by([.pod,.container]) | length) then
        error("log observation repeats a Pod/container coordinate")
      else sort_by([.pod,.container]) end
  end;

def phase9_start_observation_healthy:
  .restartCount == 0 and .lastState.terminated == null
  and ((.state.waiting.reason // "") as $reason |
    ["CrashLoopBackOff", "RunContainerError", "CreateContainerError",
     "CreateContainerConfigError"] | index($reason) == null);

def phase9_candidate_staging_healthy($image):
  (.items | type == "array")
  and all(.items[] | select(any(.spec.containers[];
      .name == "agent" and .image == $image));
    .metadata.deletionTimestamp == null
    and (.status.phase != "Failed" and .status.phase != "Unknown")
    and all((.status.containerStatuses // [])[];
      phase9_start_observation_healthy and .state.terminated == null)
    and all((.status.initContainerStatuses // [])[];
      phase9_start_observation_healthy
      and (.state.terminated == null or
        (.state.terminated.exitCode == 0 and .state.terminated.reason == "Completed"
         and (.state.terminated.signal // 0) == 0))));
