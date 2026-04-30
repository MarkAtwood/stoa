# ADR-0009: TCP IHAVE/TAKETHIS Peering Replaces gossipsub

**Status:** Accepted
**Date:** 2026-04-29
**Supersedes:** ADR-0004

---

## Context

ADR-0004 selected gossipsub per-hierarchy topics (`stoa.hier.<hierarchy>`) as
the group log dissemination layer. During implementation and early operation,
three problems emerged:

1. **Two network stacks.** The gossipsub layer required a libp2p swarm, which
   means stoa ran two separate network stacks: the existing NNTP TCP server and
   a libp2p swarm. Managing two stacks (port allocation, TLS contexts, peer
   identity, NAT traversal) doubled operational complexity.

2. **Usenet peering semantics are already solved.** RFC 4644 (MODE STREAM) and
   the IHAVE/TAKETHIS command pair provide a well-specified, widely-deployed,
   battle-hardened article transfer protocol. Every Usenet transit node already
   speaks it. Gossipsub tip advertisements plus a separate backfill mechanism
   replicated this semantics at higher complexity.

3. **gossipsub mesh overhead.** Even with per-hierarchy topics, a full-feed peer
   carries ~15–30 topics each with gossipsub mesh maintenance (heartbeat timers,
   peer scoring tables, message caches). For a transit daemon whose primary job
   is reliable article forwarding, this overhead was not justified by any benefit
   over direct IHAVE/TAKETHIS connections.

---

## Decision

The gossipsub dissemination layer is removed (commit bcd4026). Transit peering
uses direct TCP connections with IHAVE/CHECK/TAKETHIS per RFC 4644:

- Each peering session is a bidirectional TCP connection between two transit
  nodes.
- Offering side sends `CHECK <message-id>` (streaming mode) or `IHAVE
  <message-id>` (non-streaming); receiving side responds `238` (send it) or
  `431`/`438` (don't).
- Offering side sends `TAKETHIS <message-id>` followed by article bytes;
  receiving side responds `239` (accepted) or `439` (rejected).
- Back-pressure and rate limiting are applied per-session via configurable
  token-bucket controls (`transit/peering/backpressure.rs`,
  `transit/peering/rate_limit.rs`).

Group log reconciliation occurs at the article level: a node that receives an
article via TAKETHIS appends the article CID to its local Merkle-CRDT log for
each listed newsgroup. There is no separate tip advertisement mechanism; the
article transfer is the tip advertisement.

---

## Consequences

- **Single network stack.** Both NNTP reader sessions and transit peering use
  standard TCP with TLS. No libp2p dependency, no separate swarm, no NAT
  traversal complexity beyond what a standard TCP server requires.
- **Standard interop.** A stoa transit node can peer with any RFC 4644-compliant
  INN, Diablo, or Cyclone transit server, not just other stoa nodes.
- **No DHT.** Peer discovery is operator-configured (static peer list in
  `transit.toml`). Dynamic peer discovery is out of scope for v1; operators add
  peers by configuration, as they do in traditional Usenet.
- **CRDT reconciliation is implicit.** There is no separate reconcile protocol;
  article propagation via IHAVE/TAKETHIS is the reconciliation mechanism. A
  missing article is requested by its Message-ID when a peer offers it.
- **Removed code.** `transit/gossip/`, `transit/dht/`, and all libp2p
  dependencies are deleted. The `TipAdvertisement` type, gossipsub topic
  management, and DHT lookup fallback are removed.
