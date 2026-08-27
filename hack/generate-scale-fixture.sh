#!/usr/bin/env bash
set -euo pipefail

namespace_count=${UNF_SCALE_NAMESPACE_COUNT:-4}
client_replicas=${UNF_SCALE_CLIENT_REPLICAS:-4}
server_replicas=${UNF_SCALE_SERVER_REPLICAS:-2}
prefix=${UNF_SCALE_NAMESPACE_PREFIX:-unf-scale}
client_node=${UNF_SCALE_CLIENT_NODE:-unf-dev-control-plane}
server_node=${UNF_SCALE_SERVER_NODE:-unf-dev-worker}
client_image=${UNF_SCALE_CLIENT_IMAGE:-localhost/unf-test-tools:ipv6-ext-v1}
server_image=${UNF_SCALE_SERVER_IMAGE:-docker.io/library/busybox:1.37.0}

bounded_integer() {
    local name=$1
    local value=$2
    local minimum=$3
    local maximum=$4
    if [[ ! ${value} =~ ^[0-9]+$ ]] || ((value < minimum || value > maximum)); then
        echo "${name} must be an integer in [${minimum}, ${maximum}]; got ${value}" >&2
        exit 2
    fi
}

bounded_integer UNF_SCALE_NAMESPACE_COUNT "${namespace_count}" 2 16
bounded_integer UNF_SCALE_CLIENT_REPLICAS "${client_replicas}" 1 32
bounded_integer UNF_SCALE_SERVER_REPLICAS "${server_replicas}" 1 16
if [[ ! ${prefix} =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || ((${#prefix} > 48)); then
    echo "UNF_SCALE_NAMESPACE_PREFIX must be a DNS label no longer than 48 characters" >&2
    exit 2
fi
if ((namespace_count * (client_replicas + server_replicas) > 256)); then
    echo "scale fixture is bounded to 256 workload Pods" >&2
    exit 2
fi

for ((index = 0; index < namespace_count; index++)); do
    namespace="${prefix}-${index}"
    cat <<YAML
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
  labels:
    unf.network/scale-fixture: "true"
    unf.network/scale-enabled: "true"
    unf.network/scale-index: "${index}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: client
  namespace: ${namespace}
  labels:
    unf.network/scale-fixture: "true"
spec:
  replicas: ${client_replicas}
  selector:
    matchLabels:
      app: scale-client
  template:
    metadata:
      labels:
        app: scale-client
        role: client
        unf.network/scale-fixture: "true"
    spec:
      nodeSelector:
        kubernetes.io/hostname: ${client_node}
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
      containers:
        - name: client
          image: ${client_image}
          imagePullPolicy: Never
          command: ["sh", "-c", "sleep infinity"]
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: server
  namespace: ${namespace}
  labels:
    unf.network/scale-fixture: "true"
spec:
  replicas: ${server_replicas}
  selector:
    matchLabels:
      app: scale-server
  template:
    metadata:
      labels:
        app: scale-server
        role: server
        unf.network/scale-fixture: "true"
    spec:
      nodeSelector:
        kubernetes.io/hostname: ${server_node}
      containers:
        - name: server
          image: ${server_image}
          imagePullPolicy: IfNotPresent
          command:
            - sh
            - -c
            - mkdir -p /www && echo unf-scale-ok > /www/index.html && httpd -p 9090 -h /www && httpd -f -p 8080 -h /www
          ports:
            - name: http
              containerPort: 8080
            - name: denied
              containerPort: 9090
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-scale-ingress
  namespace: ${namespace}
  labels:
    unf.network/scale-fixture: "true"
spec:
  podSelector:
    matchLabels:
      role: server
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              unf.network/scale-fixture: "true"
              unf.network/scale-enabled: "true"
          podSelector:
            matchLabels:
              role: client
      ports:
        - protocol: TCP
          port: http
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-scale-egress
  namespace: ${namespace}
  labels:
    unf.network/scale-fixture: "true"
spec:
  podSelector:
    matchLabels:
      role: client
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              unf.network/scale-fixture: "true"
              unf.network/scale-enabled: "true"
          podSelector:
            matchLabels:
              role: server
      ports:
        - protocol: TCP
          port: http
YAML
done
