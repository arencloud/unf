#!/usr/bin/env bash
# Dedicated Phase 9 lab store. Never target the default or historical stores.
set -Eeuo pipefail
if (( EUID != 0 )); then
    echo 'Run this dedicated runtime through sudo.' >&2
    exit 1
fi
exec /usr/bin/podman \
    --root /var/lib/unf-kind/phase9-20260921/storage \
    --runroot /run/unf-kind-phase9-20260921 \
    --network-config-dir /var/lib/unf-kind/phase9-20260921/networks \
    --storage-driver overlay "$@"
