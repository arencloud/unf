#!/usr/bin/env bash
# Public, bounded failure evidence. Never reads credentials or private keys.
required_reply_preserve_failure_status() {
    local path name status
    for path in flows state/agents encryption/status; do
        name=${path//\//-}
        status=0
        controller_raw "/v1/$path" > "$directory/failed-$name.json" \
            2> "$directory/failed-$name.observer.log" || status=$?
        printf '%s\n' "$status" > "$directory/failed-$name.exit"
    done
}
