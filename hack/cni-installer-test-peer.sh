#!/bin/sh
# Disposable installer fixture only: never bind this peer to a live CNI socket.
set -eu
request=$(head -c 65537)
[ "${#request}" -le 65536 ]
printf '%s' "${request}" | jq -ces '
  select(length == 1) | .[0] |
  select(.operation == "status" and (.schemaVersion == 2 or .schemaVersion == 3 or .schemaVersion == 4)) |
  {schemaVersion:.schemaVersion,status:"ok",attachment:null,attachment_count:0}'
