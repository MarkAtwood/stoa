# ADR-0005: Synthetic Local Article Numbers

## Status
Accepted

## Context

RFC 3977 requires that the NNTP `GROUP` command return a low and high article
number for the named group, and that `ARTICLE`, `HEAD`, `BODY`, and `OVER`
accept article numbers as arguments. Newsreader clients (slrn, tin, pan,
Thunderbird) rely on these numbers to track read state and to request ranges of
new articles since their last connection.

usenet-ipfs identifies articles globally by CID (content-addressed, network-stable)
and by Message-ID (legacy Usenet identity). Neither is a short sequential integer.
The question is how to bridge this to the NNTP article number protocol.

Options considered:

- **Global stable article numbers** — assign a network-wide sequential number
  per group, coordinated across all nodes. Requires a distributed consensus
  protocol or a designated coordinator for each group. Coordination overhead per
  article is incompatible with a store-and-forward, partition-tolerant design.
  Any coordinator failure blocks number assignment across all peers.

- **CID-derived numbers** — map a CID to an integer deterministically
  (e.g. the first 8 bytes of the SHA-256 digest, modulo some large prime).
  Produces numbers that are stable across peers but not sequential. RFC 3977
  requires that article numbers within a group are sequential positive integers
  with no gaps, so that `NEWNEWS` and range requests work correctly. This
  approach does not satisfy that requirement.

- **Per-(group, server-instance) synthetic sequential numbers** — each reader
  instance assigns its own local sequential integers starting at 1, stored in
  SQLite, generated at ingress. Numbers are meaningful only on the instance that
  assigned them. Message-ID and CID remain the stable cross-peer identifiers.

## Decision

Article numbers are local and synthetic: per-`(group_name, reader_server_instance)`
sequential integers assigned at ingress and stored in the `article_numbers`
SQLite table as `(group_name TEXT, article_number INTEGER, cid BLOB)`.
Assignment uses `MAX(article_number) + 1` inside a SQLite transaction to
serialize concurrent inserts. The mapping is idempotent: assigning a number for
a `(group, cid)` pair that already has one returns the existing number.

The CID and Message-ID are the stable identifiers. Article numbers are a
presentation layer detail, never used as CID pointers or network-stable
references anywhere in the codebase.

## Consequences

- RFC 3977 compliance is straightforward: the reader always has dense sequential
  numbers available for `GROUP`, `ARTICLE`, `OVER`, and `NEWNEWS`.
- No distributed coordination is required for number assignment. Assignment is a
  single-process SQLite transaction.
- Two reader instances serving the same group from the same IPFS/gossipsub state
  will assign different local numbers to the same articles. Clients that migrate
  between servers will re-download read-state from scratch (this is existing
  Usenet reader behaviour; read-state is local to the client anyway).
- Clients should use `Message-ID` for cross-server identity (slrn, tin, pan, and
  Thunderbird all support Message-ID-based read state). The local number is only
  used for the `GROUP`/`OVER`/range request mechanics.
- `NEWNEWS` and high-watermark tracking work correctly within a single server
  instance. Across server instances they do not interoperate by number, which is
  consistent with how traditional Usenet transit works.
