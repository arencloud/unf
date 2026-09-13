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
    connect-timeout) printf 'Connecting to 192.0.2.1:8080... failed: Connection timed out.\n' >&2; exit 4;;
    response-timeout) printf 'Connecting to 192.0.2.1:8080... connected.\nHTTP request sent, awaiting response... Read error (Connection timed out) in headers.\n' >&2; exit 4;;
    refused) printf 'Connecting to 192.0.2.1:8080... failed: Connection refused.\n' >&2; exit 4;;
    reset) printf 'Connecting to 192.0.2.1:8080... connected.\nRead error (Connection reset by peer) in headers.\n' >&2; exit 4;;
    *) exit 2;;
esac
