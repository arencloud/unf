# ADR 0242: Admitted Predecessor Settlement

## Status

Accepted

## Context

The ADR 0241 tuple recovered the tombstoned active proof on cl02, then every
Node reached a different restart boundary: its durable pending generation had
already received controller admission, while the restored controller plan had
advanced again. Startup attempted orphan-stage cleanup against that admitted
capability. Cleanup correctly refused it, leaving TC attachment fenced, but the
ordering prevented the admitted predecessor from completing its normal
activation.

Controller admission is stronger than local preparation and weaker than map
activation. It must neither be erased as an orphan nor skipped when a newer
plan exists.

## Decision

Add an explicit causal join for a controller-admitted `Pending` recovery slot.
When its generation is older than the authenticated current plan:

1. verify that the volatile admission exactly matches both the durable
   generation cursor and pending recovery journal;
2. defer compilation and cleanup of the newer plan;
3. replay the admitted predecessor fact, rebuild its exact Linux/route/path
   proof, and consume its ordinary map-activation capability; and
4. only after that commit allow the normal plan loop to compile the successor.

An admitted `Active` revalidation remains governed by stale-active and
tombstone-aware handoff. A merely prepared, non-admitted stage remains eligible
for exact supersession cleanup. Any cursor, journal, fact, or admission mismatch
is still a hard error.

## Consequences

- A newer desired plan cannot reorder or erase an already admitted causal
  predecessor.
- No controller response is interpreted as map authority, and no persistent or
  kernel state is deleted by inference.
- Startup remains fail closed until the predecessor has traversed its complete
  proof and activation path.
- The successor is compiled only against the newly committed predecessor.
- The runtime change invalidates ADR 0241 as the deployable tuple. Fresh full
  Kind qualification, immutable image publication, and complete cl02
  qualification are required again.
