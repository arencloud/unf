#!/bin/sh
set -eu
# The fixture pins GNU Wget, whose exit 4 denotes network failure. Refuse
# implementations with different exit-code semantics rather than guessing.
case "$(wget --version 2>/dev/null)" in 'GNU Wget '*) ;; *) exit 2 ;; esac
status=0
response=$(wget -T 3 -t 1 -qO- "$1") || status=$?
if [ "$status" -eq 0 ] && [ "$response" = ok ]; then
    printf 'http-ok\n'
elif [ "$status" -eq 4 ]; then
    printf 'network-denied\n'
else
    printf 'probe-error:%s\n' "$status"
fi
