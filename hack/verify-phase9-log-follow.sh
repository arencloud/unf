#!/usr/bin/env bash
set -Eeuo pipefail
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
directory=$(mktemp -d /tmp/unf-log-follow.XXXXXX)
first=
second=
cleanup() {
    for pid in "$first" "$second"; do
        [[ -z $pid ]] || { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    done
}
trap cleanup EXIT
# An external follower cannot inherit the rollout shell's EXIT/ERR traps.
bash "$project_root/hack/phase9-follow-log.sh" "$directory/first.log" "$directory/first-observer.log" "$directory/first.exit" bash -c 'printf "first\n"; printf "diagnostic\n" >&2; exit 7' &
first=$!
bash "$project_root/hack/phase9-follow-log.sh" "$directory/second.log" "$directory/second-observer.log" "$directory/second.exit" sleep 30 &
second=$!
wait "$first"
first=
[[ $(< "$directory/first.exit") == 7 && $(< "$directory/first.log") == first && $(< "$directory/first-observer.log") == diagnostic ]]
kill -0 "$second"
for _ in $(seq 1 100); do
    [[ ! -s $directory/second.exit.started ]] || break
    sleep 0.01
done
[[ -s $directory/second.exit.started ]]
kill -TERM "$second"
wait "$second"
second=
[[ $(< "$directory/second.exit") == 143 ]]
bash "$project_root/hack/phase9-follow-log.sh" "$directory/success.log" "$directory/success-observer.log" "$directory/success.exit" true
[[ $(< "$directory/success.exit") == 0 ]]
printf 'Log followers preserve exit status and independent lifetime; evidence=%s\n' "$directory"
