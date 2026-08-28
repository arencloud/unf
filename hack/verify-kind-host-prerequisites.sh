#!/usr/bin/env bash
set -euo pipefail

for command in jq kubectl podman sysctl; do
    if ! command -v "${command}" >/dev/null; then
        echo "primary-CNI Kind prerequisite is missing: ${command}" >&2
        exit 1
    fi
done

inotify_instances=$(sysctl -n fs.inotify.max_user_instances)
if (( inotify_instances < 512 )); then
    echo "primary-CNI Kind requires fs.inotify.max_user_instances >= 512; current value is ${inotify_instances}" >&2
    echo "temporarily raise it with: sudo sysctl -w fs.inotify.max_user_instances=1024" >&2
    exit 1
fi

echo "primary-CNI Kind host prerequisites passed"
