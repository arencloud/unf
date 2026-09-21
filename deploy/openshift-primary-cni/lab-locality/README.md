# cl02 locality lab capability profile

Explicitly approved lab-only SYS_ADMIN expansion (ADR 0448). This is not a
default overlay or a least-privilege production recommendation. No image or
release pin is changed by these guarded JSON patches. Apply only to the
independently identified cl02 lab, after the matching diagnostic profile passes:

```sh
kubectl --kubeconfig "$KUBECONFIG" patch scc unf-primary-agent --type=json --patch-file deploy/openshift-primary-cni/lab-locality/scc-capability-patch.json
kubectl --kubeconfig "$KUBECONFIG" -n unf-system patch daemonset unf-agent --type=json --patch-file deploy/openshift-primary-cni/lab-locality/agent-capability-patch.json
```

The expected original capabilities, container identity, OnDelete strategy,
non-privileged/no-escalation/read-only-root profile, SELinux type and default
seccomp profile are tested before modification. Existing agent Pods are not
automatically replaced. Do not skip failed tests or silently widen other fields.
Require server-side dry-run admission of the complete new Pod template under
`unf-primary-agent` before staged image rollout and actual capability readback.

The diagnostic uses the exact container security profile but no hostPath mounts:
bounded temporary emptyDir volumes replace production writable host paths.
Its disposable service account uses the existing privileged SCC solely because
the production SCC does not allow emptyDir. The test container is explicitly
non-privileged, and runtime capability/seccomp/SELinux checks are mandatory.
This does not substitute for production-SCC admission and staged runtime tests.
