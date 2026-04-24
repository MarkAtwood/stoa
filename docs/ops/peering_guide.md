# Operator Peering Guide

## How Peering Works

### Store-and-Forward Transport

The transit daemon (`stoa-transit`) exchanges articles with other NNTP peers using the streaming protocol defined in RFC 4644: `MODE STREAM`, `CHECK`, and `TAKETHIS`. Each incoming article passes through the ingestion pipeline:

1. Write article bytes to IPFS — obtain a DAG-CBOR CIDv1.
2. Record the `message_id → CID` mapping in SQLite (`msgid_map`).
3. Append a `LogEntry` to each group named in the `Newsgroups:` header.
4. Broadcast a `TipAdvertisement` for each group on gossipsub.

Articles whose `message_id` is already in `msgid_map` are accepted idempotently — no second IPFS write occurs. This is the normal duplicate-suppression path and is not an error.

### Gossipsub Mesh

Group state is reconciled over a libp2p gossipsub mesh. Topics are **per-hierarchy, not per-group**:

| Group | Topic |
|---|---|
| `comp.lang.rust` | `stoa.hier.comp` |
| `comp.lang.c` | `stoa.hier.comp` |
| `sci.math` | `stoa.hier.sci` |
| `alt.test` | `stoa.hier.alt` |

The topic name is derived from the first dot-separated component of the group name: `<group> → stoa.hier.<hierarchy>`.

All groups in the same hierarchy share one gossipsub topic. Receivers filter messages by `group_name` inside the payload. This caps the number of active topics at the number of top-level hierarchies (typically a few dozen) rather than the number of individual groups.

### Tip Advertisements

When a node learns a new group-log tip — either via an incoming article or via a locally posted article — it broadcasts a `TipAdvertisement` on the relevant hierarchy topic:

```json
{
  "group_name": "comp.lang.rust",
  "tip_cids": ["bafyreib..."],
  "hlc_ms": 1700000000000,
  "hlc_logical": 0,
  "hlc_node_id": "0102030405060708",
  "sender_peer_id": "12D3KooW..."
}
```

Peers that receive a tip advertisement and do not recognise the listed CIDs trigger a reconciliation pull from the sender. Tip publication is best-effort: a full or absent gossipsub channel generates a warning log entry and does not fail the article ingestion.

---

## Adding Peers

### Config-file approach (static peers)

Peers are listed in `transit.toml` under `[peers]`:

```toml
[peers]
addresses = [
    "192.0.2.10:119",
    "192.0.2.20:119",
]
```

Each address is `host:port` in standard NNTP form. Addresses listed here are marked `configured = true` in the peer registry. The transit daemon connects to configured peers at startup and reconnects them if the connection drops.

`[groups]` declares which groups this instance carries:

```toml
[groups]
names = [
    "comp.lang.rust",
    "comp.lang.c",
    "sci.math",
]
```

Group names must be lowercase dot-separated labels (`[a-z0-9+\-_]` per component). Uppercase letters and empty components are rejected at startup.

### Runtime `transit peer-add`

Not yet implemented. When available, this command will insert a peer record into the `peers` SQLite table and initiate a connection without a daemon restart. Until then, edit the config file and restart the daemon.

---

## Peer Health Tracking and Reputation Scoring

### Score formula

Every peer has a floating-point health score in `[0.0, 1.0]` computed from three counters stored in the `peers` table:

```
score = 1.0 - accept_penalty - failure_penalty
      clamped to [0.0, 1.0]
```

- **accept_penalty** — if any articles have been exchanged: `(1.0 - accept_rate) * 0.5`, where `accept_rate = articles_accepted / (articles_accepted + articles_rejected)`. A peer with a 100% accept rate contributes 0 to this penalty; a peer that rejects every article contributes 0.5.
- **failure_penalty** — `min(consecutive_failures, 20) / 20 * 0.5`. A peer with 20 or more consecutive failures contributes 0.5 to this penalty.
- A brand-new peer with no history scores 1.0 (no penalty applied).

Both penalties contribute at most 0.5 each, so a peer with the worst possible history in both dimensions scores 0.0.

### Automatic blacklisting

When `consecutive_failures` reaches the configured threshold (default: 10), the peer is blacklisted for a fixed duration (default: 3600 seconds / 1 hour). The blacklisted state is stored as a Unix-millisecond timestamp (`blacklisted_until`) in the `peers` table. The blacklist expires automatically — once `now > blacklisted_until`, the peer is treated as active again without operator intervention.

Blacklisting is recorded as a `PeerBlacklisted` event in the core audit log.

A successful article ingestion from a peer resets `consecutive_failures` to zero.

### Manual blacklist management

```bash
# Blacklist a peer for 7200 seconds (2 hours):
transit peer-blacklist <peer_id> 7200

# Remove a blacklist entry immediately:
transit peer-unblacklist <peer_id>
```

`peer-unblacklist` sets `blacklisted_until = NULL` and resets `consecutive_failures` to zero.

---

## Feed Negotiation

On connection, peers exchange their group lists. The transit daemon records which groups each peer serves in the `peer_groups` table `(peer_id, group_name)`. This mapping is replaced atomically on each reconnection.

When forwarding an article, the daemon consults `peer_groups` to select only peers that serve the article's group. An article in `comp.lang.rust` is offered only to peers whose group list includes `comp.lang.rust`. This avoids sending unsolicited articles and reduces unnecessary rejections that would degrade peer health scores.

### Restricting which groups you accept or serve

To restrict your node to a specific set of groups, list only those groups under `[groups]` in `transit.toml`. Your node will not accept articles for groups not in this list, and will not advertise those groups to peers during feed negotiation.

There is no wildcard syntax in `[groups].names` — each group must be listed explicitly. This is intentional: wildcard group acceptance creates unbounded storage exposure.

---

## Monitoring Peers: `transit peer-list`

```bash
transit peer-list
transit peer-list --format json
```

**Table output:**

```
PEER_ID                                              ADDRESS              SCORE STATUS       LAST_SEEN_MS
----------------------------------------------------------------------------------------------------------
12D3KooWExamplePeerIdAAAAAAAAAAAAAAAAAAAAAAAAAAAA    192.0.2.10:119       0.950 active       1700000100000
12D3KooWExamplePeerIdBBBBBBBBBBBBBBBBBBBBBBBBBB    192.0.2.20:119       0.500 blacklisted  1700000050000
```

Columns:
- `PEER_ID` — libp2p peer identity (base58 encoded public key).
- `ADDRESS` — last known `host:port`.
- `SCORE` — health score in `[0.000, 1.000]`. Scores below 0.5 indicate a degraded peer.
- `STATUS` — `active` or `blacklisted`. A peer whose `blacklisted_until` timestamp is in the past appears as `active` even if the counter has not been reset.
- `LAST_SEEN_MS` — Unix timestamp in milliseconds of the most recent article exchange.

**Detailed per-peer view:**

```bash
transit peer-score <peer_id>
```

Output:

```
peer_id:              12D3KooW...
address:              192.0.2.10:119
score:                0.9500
status:               active
articles_accepted:    950
articles_rejected:    50
consecutive_failures: 0
last_seen_ms:         1700000100000
configured:           true
```

`configured: true` means the peer was declared in `transit.toml`; `false` means it was discovered dynamically and inserted into the registry automatically.

---

## Tor Hidden Service Configuration

No application code changes are needed to expose the NNTP, JMAP, IMAP, or SMTP listeners as Tor hidden services. Configure the external Tor daemon and bind the server listeners to `127.0.0.1` to prevent direct clearnet access.

### 1. Bind listeners to loopback

In your `transit.toml` (or reader/mail config), set every listener address to `127.0.0.1`:

```toml
[listen]
addr = "127.0.0.1:119"        # NNTP peering

[smtp]
addr = "127.0.0.1:25"
smtps_addr = "127.0.0.1:465"
```

Binding to `127.0.0.1` ensures the service is not reachable on the public network interface. Tor forwards traffic from the `.onion` port to the local address.

### 2. Configure torrc

Add a `HiddenServiceDir` and one `HiddenServicePort` directive per listener port you want to expose:

```
HiddenServiceDir /var/lib/tor/stoa/
HiddenServicePort 119  127.0.0.1:119
HiddenServicePort 25   127.0.0.1:25
HiddenServicePort 465  127.0.0.1:465
HiddenServicePort 143  127.0.0.1:143
```

Reload or restart Tor after editing `torrc`. Tor will create the hidden service directory and write the `.onion` address to `hostname`:

```
cat /var/lib/tor/stoa/hostname
# → youraddress.onion
```

### 3. Distribute the .onion address to peers

Share `youraddress.onion:119` with peers who should connect. Add it to their `[peers]` config:

```toml
[[peers.peer]]
addr = "youraddress.onion:119"
```

Peer connections over Tor use the same NNTP transit protocol and ed25519 auth handshake as clearnet connections. The Tor daemon handles the transport; the application sees a normal TCP connection.

### Notes

- Gossipsub uses libp2p's own transport stack. Tor hidden services only affect the NNTP TCP listeners, not the gossipsub mesh.
- The admin endpoint should always be bound to `127.0.0.1` (the default) and is not exposed via Tor.
- For high-volume transit peering, Tor's bandwidth and latency constraints may be a bottleneck. Consider reserving Tor for reader-facing ports (`143`, `465`) and using clearnet (firewalled) for peering port `119`.

---

## Troubleshooting

### Peer not connecting

1. Check that the address in `[peers].addresses` is reachable: `nc -z <host> <port>`.
2. Verify the daemon is listening: check the log for `listening on` at startup.
3. Check `transit peer-list` — if the peer appears as `blacklisted`, run `transit peer-unblacklist <peer_id>`.
4. Check the structured log for `consecutive_failures` increment events from that peer. High rejection rates from the remote end will trigger blacklisting.

### Messages not propagating

1. Confirm the gossipsub topic is active. The log emits a warning at `WARN` level when `publish_tips_after_post` finds no subscribers on a hierarchy topic. If this warning appears consistently, no other node is subscribed to that hierarchy.
2. Verify both nodes list the same groups. Feed negotiation uses exact group-name matching; a peer that does not list `comp.lang.rust` in its group list will not receive articles for that group.
3. Check that `TipAdvertisement` messages are being received by the remote peer. The `handle_tip_advertisement` path logs at `WARN` level if it receives an advertisement with an empty group name or empty tip list — these indicate a malformed sender.
4. If articles are arriving but not appearing in the reader, check whether the gossipsub tip advertisement reached the reader's gossip listener and triggered reconciliation. The reconciliation path logs at `INFO` level when it fetches wanted entries from a remote peer.

### Score stuck at 0.0

A peer scored at 0.0 has both maximum consecutive failures and a 0% accept rate. This typically indicates a misconfigured remote or a protocol incompatibility. Investigate the `articles_rejected` cause in the remote peer's logs, fix the underlying issue, then run `transit peer-unblacklist <peer_id>` to reset the counters and give the peer a clean slate.
