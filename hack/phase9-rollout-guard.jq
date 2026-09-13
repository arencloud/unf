# Management readiness is intentionally not required before fleet admission.
# A candidate that has restarted or terminated is not healthy staging, however.
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
