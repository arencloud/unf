#!/bin/sh
set -eu
case " $* " in *' --tries=1 '*) ;; *) exit 2;; esac
case "$*" in *'/health') ;; *) exit 2;; esac
printf 'call\n' >> "$UNF_CONTINUITY_WGET_CALLS"
case $UNF_CONTINUITY_WGET_SCENARIO in
    ok) printf '  HTTP/1.0 200 OK\n' >&2;;
    wrong-status) printf '  HTTP/1.1 503 Unavailable\n' >&2; exit 8;;
    malformed) printf 'not HTTP\n' >&2;;
    timeout) exit 124;;
    failed) exit 4;;
    *) exit 2;;
esac
