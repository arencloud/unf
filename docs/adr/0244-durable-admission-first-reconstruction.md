# ADR 0244: Durable Admission-First Reconstruction

## Status

Accepted

## Context

The ADR 0243 rollout reproduced the admitted-predecessor fence even with ADR
0242 ordering. The first startup iteration had not yet rebuilt a volatile
`ControllerAdmitted` capability, so the join saw no admission and entered
orphan cleanup. The durable generation cursor and pending recovery journal
already contained the complete admission identity; cleanup then correctly
refused to erase it.

Requiring volatile state to recognize durable admission creates an impossible
ordering dependency after every process restart.

## Decision

Recognize an admitted pending predecessor from the exact equality of the
verified durable generation cursor and verified pending recovery journal before
consulting volatile state. If the current authenticated plan is at or ahead of
that generation:

- no volatile state is valid and means proof reconstruction has not started;
- an exact `ControllerAdmitted/Pending` reconstruction is valid;
- a merely `Prepared/Pending` reconstruction is invalid because it lost the
  durable admission identity; and
- every other volatile slot, cursor mismatch, journal mismatch, or plan
  regression is invalid.

The valid no-volatile case skips orphan cleanup and successor compilation,
replays the durable fact/cursor, then rebuilds the exact Linux and path proof
before normal activation. No durable admission is manufactured: both persisted
objects must already agree byte-for-byte.

## Consequences

- Process restart no longer makes volatile reconstruction a prerequisite for
  recognizing stronger durable admission.
- Missing, stale, or equivocal durable evidence remains fail closed.
- The predecessor still completes ordinary route, path, map, and activation
  proof before its successor is compiled.
- The runtime change invalidates ADR 0243 as the deployable tuple. Fresh full
  Kind qualification, immutable publication, and complete cl02 qualification
  are required again.
