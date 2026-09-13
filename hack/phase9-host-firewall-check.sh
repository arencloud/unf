#!/bin/sh
set -eu
rules4=$(iptables-save)
rules6=$(ip6tables-save)
if printf '%s\n%s\n' "$rules4" "$rules6" | grep -Eq '(^:KUBE-(SVC|SEP|SERVICES|NODEPORTS)|^-A KUBE-(SVC|SEP|SERVICES|NODEPORTS))'; then
    echo 'legacy kube-proxy Service chains remain' >&2
    exit 1
fi
printf 'host-firewall-clean\n'
