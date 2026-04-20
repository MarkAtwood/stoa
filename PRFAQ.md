# PRFAQ: usenet-ipfs

## Press Release

**usenet-ipfs: Usenet over IPFS, with a standard NNTP interface**

*Run a newsgroup server whose storage is content-addressed and whose group state is a peer-to-peer Merkle-CRDT log — without changing a single line of your newsreader client.*

---

The Usenet news protocol has been in continuous use since 1980. Its wire format (RFC 3977 NNTP) is stable, well-understood, and supported by a long tail of mature client software. Its storage infrastructure, however, is centralized: a shrinking number of commercial news servers hold canonical copies of articles, apply their own retention policies with no public audit trail, and coordinate group state through private peering agreements.

**usenet-ipfs** replaces the storage and coordination layer while keeping the client interface unchanged. Articles are stored as content-addressed IPLD blocks in IPFS. Group state — which articles belong to which group, in what order — is a per-group Merkle-CRDT append-only log reconciled over a libp2p gossipsub overlay. Any peer can verify the log's integrity by following the Merkle chain. No central authority controls retention.

The reader server presents a standard RFC 3977 NNTP interface. Slrn, tin, pan, gnus, and Thunderbird connect to it and see an ordinary newsgroup server. They do not need to be patched, configured specially, or made aware of IPFS.

The transit daemon handles peering: receiving articles via IHAVE, storing them to IPFS, appending to the group log, and propagating tips to peers over gossipsub. Operators configure pinning policy and GC retention rules explicitly; "it's in IPFS" is not treated as a retention strategy.

usenet-ipfs is written in Rust and is open-source under the MIT license.

---

## External FAQ

**Who is this for?**

Operators who want to run Usenet infrastructure without depending on commercial backbone providers. Archivists and researchers who want a content-addressed, verifiable record of public newsgroup traffic. Developers building on IPFS who want a worked example of a Merkle-CRDT group-state protocol with a real client base.

**Do I need to change my newsreader?**

No. The reader daemon speaks RFC 3977 NNTP verbatim. Configure it the same way you would configure any other NNTP server. LIST, GROUP, ARTICLE, HEAD, BODY, OVER/XOVER, POST, and AUTHINFO all work. STARTTLS is supported.

**Can I read binary groups / NZB files?**

Not in v1. usenet-ipfs v1 is text-only. Binary groups, yEnc-encoded posts, and NZB-equivalent manifests are deferred. A placeholder epic exists and will be addressed in a future release once the text-only core is stable.

**How does article retention work?**

Explicitly. Operators configure pinning rules (by group, age, size) and a GC policy. Articles not covered by a pin are eligible for GC according to the declared policy. There is no implicit retention. The system will not quietly drop articles without a traceable policy decision.

**How does peer discovery work?**

Gossipsub topics are per-hierarchy: all `comp.*` traffic flows over the `usenet.hier.comp` topic. In-topic filtering by group name happens at each node. DHT is used as a fallback for tip discovery by peers that have been offline. Late-joining peers backfill by following parent links in the Merkle-CRDT log.

**Can I import an existing archive?**

Yes. The import tooling supports IHAVE-based ingestion, pull-style suck, and mbox backfill. Each imported article is stored to IPFS, indexed in the Message-ID↔CID map, and appended to the appropriate group log.

**How are articles authenticated?**

Every article is signed by the operator's ed25519 key before it is written to IPFS or appended to a group log. An operator cannot write an unsigned article to the log. Posters may optionally include a DID-signed payload that is passed through unchanged; the reader server exposes this in a header field for clients that understand it.

**Is there moderation?**

No, not in v1. usenet-ipfs does not implement cancel messages, NoCeM, or any allowlist/denylist mechanism. The group log is append-only. Moderation tooling is deferred to a future release.

**What is the gossipsub topic naming scheme?**

`usenet.hier.<hierarchy>` — for example, `usenet.hier.comp` for all `comp.*` groups, `usenet.hier.sci` for all `sci.*` groups. Per-group topics do not scale past a few hundred groups per peer and are not used.

**What happens to article numbers when I connect a new reader to an existing group?**

Local sequential article numbers are synthesized fresh at ingress for each `(group, reader_server)` instance. They are stored in SQLite and are stable for the lifetime of that reader instance. They are not network-stable: two reader servers serving the same group will assign different article numbers. Newsreaders that cache article numbers against a specific server will work correctly; anything that assumes article numbers are globally consistent will not.

**What IPFS node does it talk to?**

TBD. A spike issue will benchmark iroh, rust-ipfs, and raw rust-libp2p with a custom bitswap implementation, then select one. The decision will be documented before any implementation work that depends on it begins.

---

## Internal / Technical FAQ

**Why Merkle-CRDT and not a simple append-only list with vector clocks?**

A Merkle-CRDT lets any peer verify the log's integrity without trusting any other peer. The Merkle structure provides tamper evidence. The CRDT merge semantics mean late-joining peers and network partitions are handled correctly without a coordinator.

**Why gossipsub topics per-hierarchy rather than per-group?**

Per-group topics produce O(groups) subscriptions per peer. A node peering on 50,000 groups would maintain 50,000 active topic subscriptions in the gossipsub mesh, which does not scale. Per-hierarchy sharding bounds the subscription count to the number of top-level hierarchies (~20 for standard Big-8 + ISP locals). In-topic filtering is cheap.

**Why SQLite for local state?**

Article number synthesis and the overview index are write-heavy, range-query-heavy, and strictly local to one reader instance. SQLite is fast, well-tested, zero-configuration, and does not require a separate process. sqlx provides compile-time query checking. There is no scenario in this system where a distributed SQL database is justified.

**Why ed25519 for signing?**

Fast, small keys, well-audited (ed25519-dalek), and broadly interoperable. The alternative considered was wolfcrypt-rustcrypto; it was ruled out because it adds a significant FFI surface and C build dependency for no capability advantage in this use case.

**Why not reuse an existing Usenet transport like Diablo or INN?**

Those systems are designed around a centralized spool. Retrofitting content-addressed IPFS storage onto them would require replacing their storage layer, which is not a thin abstraction. Writing from scratch in Rust lets us design the storage model correctly from the start and avoids inheriting decades of C legacy code.

**Why RFC 3977 verbatim? Why not extend the protocol to expose CIDs?**

Because the client base for NNTP is large and mostly unmaintained. Extensions that require client changes will be ignored. RFC 3977 compliance is the only way to be compatible with slrn, tin, pan, gnus, and Thunderbird without forking them. CIDs are an implementation detail visible to peers and operators, not to newsreader clients.

**What is the threat model for the POST path?**

All NNTP input — commands, headers, article bodies — is treated as attacker-controlled. Group names, Message-IDs, header field lengths, and article sizes are validated at ingress before any storage operation. Message-IDs from the wire are not used as map keys until their format is verified. The operator key is never logged; signing happens in a dedicated module that does not expose the key material to application logic.

**What does "no moderation in v1" mean for spam?**

Operators control which peers they accept IHAVE from, which gives them a first-order spam filter at the transit layer. Beyond that, v1 provides no spam mitigation. A security spike issue will evaluate proof-of-work stamps (e.g. Hashcash) versus rate-limited operator signing as spam mitigation mechanisms for a future release.

**When will v1 be ready?**

The project is in the planning phase. The issue graph is being built out using Beads. No implementation code exists yet. There is no committed timeline.
