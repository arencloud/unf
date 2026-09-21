#!/usr/bin/env bash
# Embedded into the immutable diagnostic command; no host filesystem mounts.
set -Eeuo pipefail
umask 077
trap 'printf "locality-lab-profile: FAIL line=%s\n" "$LINENO" >&2' ERR
for field in CapPrm CapEff CapBnd; do
    value=$(awk -v key="$field:" '$1==key {print $2}' /proc/self/status)
    printf 'locality-lab-profile: observed %s=%s\n' "$field" "$value"
    [[ $value == 000000c000201000 ]]
done
awk '/^(NoNewPrivs|Seccomp):/ {print "locality-lab-profile: observed " $0}' /proc/self/status
printf 'locality-lab-profile: observed selinux=%s\n' "$(< /proc/self/attr/current)"
[[ $(awk '$1=="NoNewPrivs:" {print $2}' /proc/self/status) == 1 ]]
[[ $(awk '$1=="Seccomp:" {print $2}' /proc/self/status) == 2 ]]
[[ $(< /proc/self/attr/current) == *:spc_t:* ]]
[[ $(< /sys/fs/selinux/enforce) == 1 ]]
printf 'locality-lab-profile: PASS effective=c000201000 no-new-privs=true seccomp=filter selinux=spc_t,enforcing\n'
exec "$@"
