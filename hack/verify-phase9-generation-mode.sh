#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jq -L "${root}/hack" -n -e '
  include "phase9-qualification";
  [range(0;5) | {epochs:[]}] as $native |
  [range(0;5) | {epochs:[388]}] as $required |
  [($native | phase9_generation_mode_valid("native")),
   ($required | phase9_generation_mode_valid("required")),
   ($native | phase9_generation_mode_valid("required") | not),
   ($required | phase9_generation_mode_valid("native") | not),
   ($required | .[0].epochs=[] | phase9_generation_mode_valid("required") | not),
   ($required | .[0].epochs=[] | phase9_generation_mode_valid("any")),
   ($native | .[0].epochs=null | phase9_generation_mode_valid("native") | not),
   ($required | .[0].epochs=[0] | phase9_generation_mode_valid("required") | not),
   ($required | .[0].epochs=["388"] | phase9_generation_mode_valid("required") | not),
   ($required | .[0].epochs=[1.5] | phase9_generation_mode_valid("required") | not),
   ([] | phase9_generation_mode_valid("native") | not),
   ($native | phase9_generation_mode_valid("typo") | not)] | all
' >/dev/null
echo "Phase 9 generation mode rejects Native-as-Required, mixed and malformed journals"
