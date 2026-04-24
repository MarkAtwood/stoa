# ADR-0004: Gossipsub Topics Per Hierarchy, Not Per Group

## Status
Accepted

## Context

The group log dissemination layer uses libp2p gossipsub to broadcast tip
advertisements between nodes. A gossipsub mesh maintains a set of active peer
connections per topic. Each additional topic imposes overhead: peer scoring
tables, heartbeat timers, message caches, and mesh maintenance traffic scale
with the number of subscribed topics per peer.

A realistic stoa deployment may carry thousands of active groups
(e.g. all of `comp.*`, `sci.*`, `alt.*`, `rec.*`). If each group is a
separate gossipsub topic, a peer that subscribes to 5 000 groups maintains
5 000 mesh connections. At the gossipsub default mesh degree (D=6), that is
30 000 active TCP connections per peer. This does not scale.

Two granularities were considered:

- **Per-group topics** — one topic per group name (e.g. `usenet.group.comp.lang.rust`).
  Tip advertisements are delivered only to subscribers of that specific group.
  Mesh overhead scales linearly with subscribed group count. Unworkable past a
  few hundred groups per peer.

- **Per-hierarchy topics** — one topic per top-level Usenet hierarchy
  (e.g. `stoa.hier.comp` covers all of `comp.*`). Peers interested in any
  `comp.*` group subscribe to `stoa.hier.comp`. The group name is carried
  inside the message payload and filtered in the message handler. Mesh overhead
  scales with the number of top-level hierarchies (~15–30 in practice), not with
  the number of groups.

A third option — a single global topic for all groups — was considered and
rejected: it routes every tip advertisement to every peer regardless of interest,
wasting bandwidth on unsubscribed groups.

## Decision

Gossipsub topics are per hierarchy, using the naming scheme
`stoa.hier.<hierarchy>`, where `<hierarchy>` is the first dot-separated
component of the group name. Examples:

- `comp.lang.rust` → `stoa.hier.comp`
- `sci.physics` → `stoa.hier.sci`
- `alt.folklore.computers` → `stoa.hier.alt`

The `group_name` field inside each `TipAdvertisement` message is used to filter
at the receiver: a node interested only in `comp.lang.rust` subscribes to
`stoa.hier.comp` and discards advertisements for groups it does not carry.

Topic naming uses the `stoa.hier.` prefix (not `usenet/` or `nntp/`) to avoid
collisions with other applications sharing the same libp2p DHT.

## Consequences

- The number of active gossipsub topics per peer is bounded by the number of
  top-level hierarchies the peer carries, not by its group count. In practice
  this is 15–30 topics for a full-feed peer, and as few as 1 for a
  single-hierarchy reader.
- In-message filtering adds a small CPU cost per received tip advertisement.
  The cost is a string prefix comparison and a local group-membership lookup;
  it is negligible relative to the gossipsub message handling overhead.
- Backfill (fetching unknown log entries after receiving a tip advertisement)
  must filter by group name after receipt because the received payload may
  contain tips for groups the local node does not carry. This is handled in
  `transit/gossip/tip_advert.rs::handle_tip_advertisement`.
- Peers that carry only a subset of groups within a hierarchy receive tip
  advertisements for groups they do not carry. The discarded messages are small
  (JSON tip payloads, no article content), so the wasted bandwidth is
  proportional to the ratio of unsubscribed-to-subscribed groups within the
  hierarchy, which is acceptable.
