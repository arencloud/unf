#!/usr/bin/env bash
# Run as a separate background process, never source into a rollout shell.
# Stream status is recorded explicitly; the caller must check every exit file.
set -uo pipefail
log=${1:?log path}
observer=${2:?observer error path}
exit_file=${3:?exit status path}
shift 3
[[ $# -gt 0 && ! -e $log && ! -e $observer && ! -e $exit_file && ! -e $exit_file.started ]] || exit 2
umask 077
"$@" > "$log" 2> "$observer" &
stream_pid=$!
trap 'kill "$stream_pid" 2>/dev/null || true' TERM INT
printf '%s\n' "$stream_pid" > "$exit_file.started"
wait "$stream_pid"
result=$?
trap - TERM INT
# If a signal interrupted wait, reap the explicitly stopped owned stream.
wait "$stream_pid" 2>/dev/null || true
printf '%s\n' "$result" > "$exit_file"
