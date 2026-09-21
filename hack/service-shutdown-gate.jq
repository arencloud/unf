# Container termination can precede the Pod's terminal phase in the API.
# Neither a replaced Pod nor a restart is a successful shutdown observation.
def shutdown_fixture_terminal($uid):
  .metadata.uid == $uid and
  (.status.phase == "Succeeded" or .status.phase == "Failed") and
  (.status.containerStatuses | length == 1 and
    all(.[]; .state.terminated != null));

def shutdown_fixture_succeeded($uid):
  shutdown_fixture_terminal($uid) and .status.phase == "Succeeded" and
  .spec.hostPID != true and .spec.hostNetwork != true and
  (.status.containerStatuses | all(.[];
    .restartCount == 0 and .state.terminated.exitCode == 0 and
    .state.terminated.reason == "Completed"));
