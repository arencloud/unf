#!/usr/bin/env bash
# Sourced by the reply gate. One tokenless host-network capture, no host mounts.
required_reply_preserve_failure_capture() {
    phase9_capture_finish "$directory/failed-capture" |
      jq -ce 'del(.explicitStopAfterFault) + {explicitStopAfterTraffic:true}'
}

required_reply_capture_start() {
    local family
    capture_pod=underlay-capture
    capture_container_path=/capture/required-reply.pcap
    required_addresses=()
    native_addresses=()
    for family in required-client native-client; do
        mapfile -t addresses < <(jq -r --arg pod "$family" '.items[]|select(.kind=="Pod" and .metadata.name==$pod)|.status.podIPs[].ip' "$directory/fixture.json")
        [[ ${#addresses[@]} == 2 ]]
        if [[ $family == required-client ]]; then required_addresses=("${addresses[@]}"); else native_addresses=("${addresses[@]}"); fi
    done
    required_filter="(host ${required_addresses[0]} or host ${required_addresses[1]}) and (tcp or udp)"
    native_filter="(host ${native_addresses[0]} or host ${native_addresses[1]}) and (tcp or udp)"
    capture_filter="(udp and (port 51820 or port 51821)) or ($required_filter) or ($native_filter)"
    "${read_api[@]}" label namespace "$namespace" pod-security.kubernetes.io/enforce=privileged >/dev/null
    "${read_api[@]}" -n "$namespace" create serviceaccount capture >/dev/null
    if [[ $context != kind-* ]]; then
        "${apply[@]}" >/dev/null <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: capture-scc, namespace: $namespace}
rules:
  - apiGroups: [security.openshift.io]
    resources: [securitycontextconstraints]
    resourceNames: [privileged]
    verbs: [use]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: capture-scc, namespace: $namespace}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: capture-scc}
subjects: [{kind: ServiceAccount, name: capture, namespace: $namespace}]
EOF
    fi
    "${apply[@]}" >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $capture_pod, namespace: $namespace}
spec:
  serviceAccountName: capture
  automountServiceAccountToken: false
  nodeName: $source_node
  hostNetwork: true
  dnsPolicy: Default
  restartPolicy: Never
  volumes: [{name: capture, emptyDir: {sizeLimit: 64Mi}}]
  containers:
    - name: tcpdump
      image: $UNF_TEST_TOOLS_IMAGE
      imagePullPolicy: IfNotPresent
      command: [/usr/bin/timeout]
      args: ["--signal=INT", "300", "/usr/bin/tcpdump", "-U", "-ni", "$UNF_REQUIRED_REPLY_CAPTURE_INTERFACE", "-w", "$capture_container_path", "$capture_filter"]
      securityContext: {privileged: true}
      resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {cpu: 500m, memory: 128Mi}}
      volumeMounts: [{name: capture, mountPath: /capture}]
    - name: keeper
      image: $UNF_TEST_TOOLS_IMAGE
      imagePullPolicy: IfNotPresent
      command: [/bin/sh, -ec, "trap : TERM INT; sleep infinity & wait"]
      securityContext: {privileged: true}
      resources: {requests: {cpu: 1m, memory: 8Mi}, limits: {cpu: 100m, memory: 32Mi}}
      volumeMounts: [{name: capture, mountPath: /capture}]
EOF
    "${kc[@]}" -n "$namespace" wait --for=condition=Ready "pod/$capture_pod" --timeout=180s >/dev/null
    "${read_api[@]}" -n "$namespace" logs "$capture_pod" -c tcpdump > "$directory/capture-start.log"
    rg -q "listening on $UNF_REQUIRED_REPLY_CAPTURE_INTERFACE," "$directory/capture-start.log"
}

required_reply_capture_finish() {
    local lifecycle wireguard required native capture_sha
    lifecycle=$(phase9_capture_finish "$directory/capture" |
      jq -ce 'del(.explicitStopAfterFault) + {explicitStopAfterTraffic:true}')
    wireguard=$(tcpdump -nn -r "$directory/capture/received.pcap" 'udp and (port 51820 or port 51821)' 2> "$directory/capture/decode-wg.log" | wc -l)
    required=$(tcpdump -nn -r "$directory/capture/received.pcap" "$required_filter" 2> "$directory/capture/decode-required.log" | wc -l)
    native=$(tcpdump -nn -r "$directory/capture/received.pcap" "$native_filter" 2> "$directory/capture/decode-native.log" | wc -l)
    (( wireguard > 0 && required == 0 && native > 0 ))
    capture_sha=$(sha256sum "$directory/capture/received.pcap" | awk '{print $1}')
    jq -n --argjson lifecycle "$lifecycle" --argjson wireguard "$wireguard" --argjson required "$required" --argjson native "$native" \
      --arg digest "$capture_sha" --arg interface "$UNF_REQUIRED_REPLY_CAPTURE_INTERFACE" \
      '{lifecycle:$lifecycle,interface:$interface,sha256:$digest,wireguardFrames:$wireguard,requiredPlaintextFrames:$required,nativePlaintextFrames:$native}' \
      > "$directory/capture-summary.json"
}
