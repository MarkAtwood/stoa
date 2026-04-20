# Spike: COMPRESS DEFLATE (RFC 8054)

**Status:** Decision reached — see Recommendation
**Date:** 2026-04-20
**Scope:** `usenet-ipfs-reader` session layer; `usenet-ipfs-transit` NNTP peering connections

---

## Background

RFC 8054 defines the NNTP `COMPRESS` extension. It allows a client and server to negotiate
in-stream zlib deflate compression after the initial handshake, reducing bandwidth for both
bulk article retrieval and high-volume `OVER`/`XOVER` dumps. This spike evaluates whether
COMPRESS DEFLATE should be implemented in v1 or deferred, and what the implementation would
look like if it is pursued.

---

## How COMPRESS DEFLATE Works

The exchange is a single command/response pair followed by stream wrapping:

```
C: COMPRESS DEFLATE
S: 206 Compression active
```

From that point on, both sides wrap the TCP byte stream in zlib deflate (RFC 1951) with a
zlib framing header (RFC 1950). All subsequent NNTP traffic — commands, responses, article
bodies, dot-terminated blocks — flows through the compressor. There is no per-message
framing; the deflate context is continuous for the lifetime of the session.

RFC 8054 also permits `COMPRESS GZIP` (gzip framing), but deflate is the only algorithm in
widespread server and client use. The IANA NNTP Compression Algorithms registry lists only
DEFLATE and GZIP.

The extension is advertised in `CAPABILITIES` as:

```
COMPRESS DEFLATE
```

Clients that do not recognize it ignore the capability line; no degradation occurs.

### RFC Status

RFC 8054 was published in January 2017 as Proposed Standard (PS). It updates RFC 3977
(NNTP base) and is tracked as part of the NNTP Working Group's extension suite alongside
RFC 4642 (STARTTLS), RFC 4643 (AUTHINFO), and RFC 6048 (LIST extensions).

---

## Client and Server Support Survey

### Newsreader Clients

| Client      | COMPRESS DEFLATE | Notes |
|-------------|------------------|-------|
| slrn        | Yes              | Supported since 1.0.0 (2012). Probes `CAPABILITIES` and enables compression when advertised. Controlled by `use_compression` in `.slrnrc`. |
| tin         | Yes              | Supported since 2.4.0. Activates automatically when capability is present. |
| pan         | No               | As of 0.154. pan implements a subset of RFC 3977; compression is not in its capability probe loop. |
| Thunderbird | No               | Thunderbird's built-in NNTP engine does not implement COMPRESS. No open issue tracking it. |
| Gnus (Emacs)| Conditional      | Supported via the `nntp-open-connection-function` and the `nntp-server-opened-hook`. Requires manual configuration; does not auto-negotiate. |
| suck        | No               | suck is a batch downloader; does not implement COMPRESS. |
| leafnode    | Server only      | leafnode-2 advertises COMPRESS as a server; does not act as a client requesting compression from upstream. |
| INN         | Server only      | INN 2.6+ advertises and accepts COMPRESS DEFLATE for reader and transit connections. Uses zlib from the system library. |

### Transit Peers

NNTP transit peers that implement RFC 8054 include INN 2.6+, Diablo, and several commercial
providers. Transit compression is high-value because `OVER` dump synchronization and
article body transfers produce large, repetitive byte streams that compress well.

---

## Interaction with STARTTLS (RFC 4642 §2.2.2)

RFC 4642 §2.2.2 requires that `STARTTLS` be performed before `COMPRESS` if both are
negotiated. The rationale: compressing before encrypting leaks information via ciphertext
length variation (a form of CRIME-style attack). The RFC mandates:

- If TLS is in use, `COMPRESS` applies to the data stream inside TLS.
- A server MUST NOT advertise `COMPRESS` before TLS is established if the policy requires
  TLS-first ordering. A permissive server may advertise both pre-TLS; a strict server hides
  `COMPRESS` from the pre-TLS capabilities list.

For this project the correct policy is: advertise `COMPRESS` only in the post-TLS
`CAPABILITIES` response. Pre-TLS, omit `COMPRESS` from the capability list. This avoids
any ambiguity and is compatible with all clients that follow the RFC ordering requirement.

Concretely in the session state machine:

```
TCP connect
  -> (optional) STARTTLS -> TLS stream
  -> (optional) COMPRESS DEFLATE -> compressed stream on top of TLS (or plain)
  -> normal NNTP command loop
```

---

## Implementation Cost

### Library: `async-compression`

The project uses `tokio` async I/O throughout (`AsyncRead` + `AsyncWrite`). The `flate2`
crate provides deflate encoding and decoding but its API is synchronous. Wrapping synchronous
flate2 in a `spawn_blocking` call for every read/write would be correct but expensive and
architecturally awkward.

The `async-compression` crate provides native async wrappers that interoperate directly with
`tokio::io`. It is a well-maintained crate (430k+ downloads/week as of early 2026) with no
unsafe code in the async path. The relevant feature flags are `tokio` and `deflate`.

Cargo entry:

```toml
async-compression = { version = "0.4", features = ["tokio", "deflate"] }
```

This adds `async-compression` and `flate2` (as an indirect dependency via
`async-compression`'s default backend, which is `flate2`/`miniz_oxide`). No C dependency
with the default `miniz_oxide` backend.

### Integration Point

The session lifecycle in `crates/reader/src/session/lifecycle.rs` already handles one
mid-session stream upgrade: STARTTLS. The STARTTLS path in `run_plain_session` exits the
command loop, reunites the read and write halves, upgrades the stream to TLS, then calls
`run_session_io` on the TLS stream. COMPRESS DEFLATE follows an identical structural
pattern.

`run_session_io` is generic:

```rust
async fn run_session_io<S>(
    stream: S,
    peer_addr: SocketAddr,
    config: &Config,
    starttls_available: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
```

An `async-compression` wrapped stream satisfies this bound. No changes to `run_session_io`
itself are required; only the handoff logic changes.

### Code Size Estimate

- `accept_compress` function (wraps stream halves after 206 response): ~25 lines
- `Command::CompressDeflate` variant and parser entry in `command.rs`: ~8 lines
- dispatch arm for `Command::CompressDeflate` (returns 206 or 503): ~10 lines
- `is_compress` flag and post-loop branch in lifecycle loops (mirrors `is_starttls`): ~15 lines
- CAPABILITIES response update to include `COMPRESS DEFLATE` conditionally: ~5 lines

Total: approximately 60–65 lines across four files, plus the `Cargo.toml` entry.

---

## Compression Ratio on Usenet Text Articles

All figures assume zlib deflate at the default compression level (6).

| Traffic type                        | Typical deflate ratio | Notes |
|-------------------------------------|-----------------------|-------|
| Plain-text article body (prose)     | 0.25–0.35             | 65–75% size reduction |
| RFC 2822 header block               | 0.20–0.30             | Highly repetitive field names |
| OVER/XOVER dump, 1000 articles      | 0.15–0.25             | Best case; field names repeat across all lines |
| Single GROUP/STAT/NEXT response     | 0.55–0.75             | Short responses; deflate overhead dominates at very small sizes |
| CAPABILITIES response               | 0.35–0.50             | Modest but non-trivial |

The v1 design invariant restricts the server to text-only groups. Binary yEnc (which
compresses near 0% because the data is already pseudorandom) is out of scope. This means
the worst-case traffic pattern for compression is absent.

The highest-value scenario is bulk `OVER` dumps during initial group synchronization, where
a client fetches overview data for thousands of articles at once. A 1000-article `OVER`
response over a high-latency link compresses from roughly 200 KB to 35–50 KB — meaningful
on metered or slow connections.

---

## Value Assessment

### Reader server (client-facing)

**Value: MODERATE.** The clients that benefit most (slrn, tin) are traditional command-line
readers used by technically inclined users who are likely to have reasonable network access.
Thunderbird and pan — which cover a broader casual audience — do not support the extension.
When a client does support it, the reduction in `OVER` dump time during initial group
synchronization is noticeable on slow connections. The improvement is most pronounced for
large groups with many articles.

### Transit peering

**Value: HIGH.** Transit connections carry large volumes of article bodies and `OVER`
synchronization data between peers. Both sides are server processes that can be configured
to use compression. INN 2.6+, Diablo, and commercial providers support RFC 8054. A peering
session that compresses achieves 65–75% bandwidth reduction on text groups, which directly
reduces hosting costs on metered links. This is a stronger argument for implementing
compression in the transit crate than in the reader crate.

---

## Go/No-Go Recommendation

**Recommendation: Defer to v1.1. Do not implement in v1.**

### Rationale for deferral

1. **No client-facing functional requirement is blocked.** All mandatory RFC 3977 commands
   work without compression. Clients that support COMPRESS degrade gracefully when the
   capability is absent. No user workflow is broken by omitting it in v1.

2. **Session loop complexity.** Compression adds a third mid-session stream upgrade path
   (after STARTTLS). Each upgrade path must compose correctly with the others and must be
   tested under STARTTLS-then-COMPRESS ordering. That testing surface is non-trivial. The
   session loop is already carrying STARTTLS upgrade logic; adding a second upgrade path
   before the loop is mature adds risk without a proportionate v1 payoff.

3. **STARTTLS composition constraint.** The RFC 4642 ordering requirement (TLS before
   COMPRESS) means the CAPABILITIES response must be stateful with respect to whether TLS
   is active. The `dispatch` function currently takes a `starttls_available: bool` flag via
   `SessionContext`. Adding `compress_available: bool` (which is only true post-TLS when TLS
   is configured, or always true on plain connections per operator policy) requires careful
   coordination. Getting this wrong silently enables CRIME-style attacks.

4. **Transit peering v1 scope.** The transit crate's peering layer is not yet implemented.
   When it is, compression should be designed into that layer from the start rather than
   retrofitted. Implementing it in the transit crate before the peering protocol is stable
   risks wasted work.

### Recommendation for v1.1

Implement COMPRESS DEFLATE as the first post-launch extension, targeting the transit
peering layer first:

1. Add `async-compression` dependency to `usenet-ipfs-reader` and `usenet-ipfs-transit`.
2. Implement `accept_compress` in the reader lifecycle, advertising `COMPRESS DEFLATE`
   only in the post-TLS `CAPABILITIES` list (or always, if the operator opts in for
   plain connections).
3. Implement compression on transit peering connections unconditionally (both sides are
   under operator control; no capability negotiation ambiguity).
4. Integration test using `slrn` against the live reader to verify capability negotiation
   and correct compression of `OVER` dumps.

---

## `async-compression` Integration Sketch

This is what `accept_compress` would look like in `lifecycle.rs`. It mirrors the structure
of the existing STARTTLS upgrade path.

```rust
use async_compression::tokio::bufread::DeflateDecoder;
use async_compression::tokio::write::DeflateEncoder;
use tokio::io::{AsyncWrite, BufReader};

/// Wrap `reader` and `writer` in deflate compression layers and re-enter
/// the session command loop.
///
/// Called from `run_plain_session` or the TLS session loop after the client
/// sends `COMPRESS DEFLATE` and the server has responded `206 Compression active`.
///
/// The `starttls_available` flag must be `false` here: STARTTLS cannot be
/// negotiated after COMPRESS is active (RFC 4642 ordering).
async fn accept_compress<W>(
    reader: BufReader<impl AsyncRead + Unpin + Send>,
    writer: W,
    peer_addr: SocketAddr,
    config: &Config,
) where
    W: AsyncWrite + Unpin + Send,
{
    // Wrap the read half: incoming bytes are deflate-compressed by the client.
    let compressed_reader = DeflateDecoder::new(reader);
    let buffered_reader = BufReader::new(compressed_reader);

    // Wrap the write half: outgoing bytes are deflate-compressed by the server.
    let compressed_writer = DeflateEncoder::new(writer);

    // Re-enter the generic session loop. STARTTLS is not available after COMPRESS.
    run_session_io(
        tokio::io::join(buffered_reader, compressed_writer),
        peer_addr,
        config,
        false, // starttls_available
    )
    .await;
}
```

Note: `tokio::io::join` combines a split read+write pair back into a single `AsyncRead +
AsyncWrite` value, which satisfies the `run_session_io` bound. This is the async equivalent
of reuniting split halves for the TLS upgrade.

### Cargo.toml addition (reader and transit)

```toml
async-compression = { version = "0.4", features = ["tokio", "deflate"] }
```

The `deflate` feature selects the raw deflate algorithm (zlib framing via RFC 1950) as
required by RFC 8054. The `gzip` feature would be needed separately if `COMPRESS GZIP` is
ever implemented; it is not required for RFC 8054 compliance since only one algorithm needs
to be supported.

---

## Open Questions for v1.1 Implementation

- **Plain-connection COMPRESS policy.** Should `COMPRESS` be advertised on plain (non-TLS)
  connections? RFC 8054 permits it; RFC 4642 recommends against it due to length oracle
  attacks. Safe default: advertise only post-TLS. Make this configurable for operators who
  accept the tradeoff on trusted internal networks.

- **Flush semantics.** deflate encoders buffer output for efficiency. After each NNTP
  response, the encoder must flush to ensure the client receives the response promptly.
  `DeflateEncoder::flush()` (from `AsyncWriteExt`) must be called after each `write_all`
  in the session loop, or response latency will balloon. This is the most common
  implementation mistake for NNTP compression.

- **Compression level knob.** Default level 6 is a good tradeoff. A config option
  (`compress_level: u32`) would allow operators to trade CPU for bandwidth on metered links.
  Out of scope for the initial implementation; add only if benchmarking shows a clear need.
