#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
certificate_dir=${UNF_INTERNAL_TLS_DIR:-"${project_root}/.tools/kind-internal-tls"}

command -v kubectl >/dev/null
command -v openssl >/dev/null

install -d -m 0700 "${certificate_dir}"
ca_key=${certificate_dir}/ca.key
ca_cert=${certificate_dir}/ca.crt
server_key=${certificate_dir}/tls.key
server_csr=${certificate_dir}/tls.csr
server_cert=${certificate_dir}/tls.crt
server_extensions=${certificate_dir}/tls.ext

if [[ ! -s ${ca_key} || ! -s ${ca_cert} ]] \
    || ! openssl x509 -checkend 86400 -noout -in "${ca_cert}" >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
        -subj '/CN=UNF disposable development CA' \
        -keyout "${ca_key}" -out "${ca_cert}" >/dev/null 2>&1
fi

if [[ ! -s ${server_key} || ! -s ${server_cert} ]] \
    || ! openssl x509 -checkend 86400 -noout -in "${server_cert}" >/dev/null 2>&1 \
    || ! openssl verify -CAfile "${ca_cert}" "${server_cert}" >/dev/null 2>&1 \
    || ! openssl x509 -checkhost unf-primary-controller.internal \
        -noout -in "${server_cert}" >/dev/null 2>&1; then
    openssl req -new -newkey rsa:2048 -nodes -sha256 \
        -subj '/CN=unf-controller.unf-system.svc.cluster.local' \
        -keyout "${server_key}" -out "${server_csr}" >/dev/null 2>&1
    printf '%s\n' \
        'basicConstraints=critical,CA:FALSE' \
        'keyUsage=critical,digitalSignature,keyEncipherment' \
        'extendedKeyUsage=serverAuth' \
        'subjectAltName=DNS:unf-controller,DNS:unf-controller.unf-system,DNS:unf-controller.unf-system.svc,DNS:unf-controller.unf-system.svc.cluster.local,DNS:unf-primary-controller.internal' \
        >"${server_extensions}"
    openssl x509 -req -sha256 -days 365 \
        -in "${server_csr}" -CA "${ca_cert}" -CAkey "${ca_key}" \
        -CAcreateserial -extfile "${server_extensions}" \
        -out "${server_cert}" >/dev/null 2>&1
fi

chmod 0600 "${ca_key}" "${server_key}"
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
"${kc[@]}" apply -f "${project_root}/deploy/kubernetes/namespace.yaml" >/dev/null
"${kc[@]}" -n unf-system create secret tls unf-internal-tls \
    --cert="${server_cert}" --key="${server_key}" \
    --dry-run=client -o yaml | "${kc[@]}" apply -f - >/dev/null
"${kc[@]}" -n unf-system create configmap unf-internal-ca \
    --from-file=ca.crt="${ca_cert}" \
    --dry-run=client -o yaml | "${kc[@]}" apply -f - >/dev/null

echo "configured disposable UNF internal TLS trust for ${context}"
