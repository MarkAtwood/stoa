# NNTP Input Validation Audit

**Date:** 2026-04-19
**Auditor:** read-only static analysis of current codebase
**Scope:** All points where attacker-controlled input enters the system via NNTP
(reader path) or peer transit (IHAVE/CHECK/TAKETHIS path). No source files were
modified.

---

## Audit Scope

This audit covers every location where external input enters the stoa
system:

- Command-line parsing (`crates/reader/src/session/command.rs`)
- Reader session dispatch (`crates/reader/src/session/dispatch.rs`)
- Per-command handlers (`crates/reader/src/session/commands/`)
- POST article body reading and validation (`crates/reader/src/session/commands/post.rs`,
  `crates/reader/src/post/validate_headers.rs`)
- Transit peering ingestion (`crates/transit/src/peering/ingestion.rs`)
- Core article validation (`crates/core/src/validation.rs`)
- Group name type constructor (`crates/core/src/article.rs`)
- All SQLite query sites (`crates/core/src/msgid_map.rs`,
  `crates/reader/src/store/article_numbers.rs`,
  `crates/reader/src/store/overview.rs`)

Items explicitly out of scope for this audit: TLS negotiation internals,
operator configuration files, gossipsub wire protocol parsing.

---

## Summary of Findings

- **SQL injection:** Not possible. Every query site uses `sqlx` parameterized
  binds (`?` placeholders). No string-interpolated SQL found anywhere in the
  codebase.
- **Shell injection:** Not possible. No user input is passed to a shell or
  exec'd as a subprocess at any point in the codebase.
- **Overall gap count:** 7 gaps identified (see "Gaps Found" section below).

---

## Table 1 — Command Parser Layer

**File:** `crates/reader/src/session/command.rs` — `parse_command()`

| Input | Source | Max Length | Format Check | SQL Safe | Shell Safe | Gap |
|-------|--------|-----------|-------------|---------|------------|-----|
| Command line (entire) | `parse_command()` | 512 bytes (RFC 3977 §3.1.3) enforced; `LineTooLong` error returned | Case-folded verb matched against known set | N/A | Yes | No |
| GROUP name argument | `parse_command()` → `Command::Group(rest)` | Bounded by 512-byte command line limit | Not validated at parse time; passed raw; `GroupName::new()` called later in dispatch | N/A | Yes | Yes — see Gap 1 |
| ARTICLE/HEAD/BODY/STAT message-id | `parse_article_ref()` | Bounded by 512-byte line | Starts-with-`<` heuristic only; not validated for `@`, whitespace, or length | N/A | Yes | Yes — see Gap 2 |
| ARTICLE/HEAD/BODY/STAT article number | `parse_article_ref()` | Bounded by 512-byte line | `s.parse::<u64>()` — integer parse; overflow impossible (returns None on failure) | N/A | Yes | No |
| OVER/XOVER range (N, N-, N-M) | `parse_range()` | Bounded by 512-byte line | `parse::<u64>()` with `unwrap_or(0)` fallback; silently coerces invalid input to 0 | N/A | Yes | Yes — see Gap 3 |
| OVER/XOVER message-id | `parse_command()` | Bounded by 512-byte line | Starts-with-`<` heuristic only; not validated further | N/A | Yes | Yes — see Gap 2 (same) |
| LIST ACTIVE wildmat | `parse_command()` → `ListSubcommand::Active` | Bounded by 512-byte line; wildmat string not separately extracted at parse time; passed as None in dispatch stub | No format validation on wildmat string | N/A | Yes | Yes — see Gap 4 |
| NEWGROUPS date/time | `parse_command()` | Bounded by 512-byte line | Stored as raw `String`; no date/time format validation at parse time | N/A | Yes | Yes — see Gap 5 |
| NEWNEWS wildmat, date/time | `parse_command()` | Bounded by 512-byte line | Wildmat stored as raw `String`; date/time stored as raw `String`; no format validation | N/A | Yes | Yes — see Gap 5 |
| IHAVE message-id | `parse_command()` | Bounded by 512-byte line | Not validated at parse time; passed raw to dispatch | N/A | Yes | Yes — see Gap 2 (same) |
| AUTHINFO USER username | `parse_command()` | Bounded by 512-byte line | No validation on username value | N/A | Yes | No (stub; not persisted) |
| AUTHINFO PASS password | `parse_command()` | Bounded by 512-byte line | No validation on password value | N/A | Yes | No (stub; not persisted) |

---

## Table 2 — GROUP / NEXT / LAST / STAT Command Handlers

**File:** `crates/reader/src/session/commands/group.rs`

| Input | Source | Max Length | Format Check | SQL Safe | Shell Safe | Gap |
|-------|--------|-----------|-------------|---------|------------|-----|
| GROUP name (from `Command::Group`) | `group_select()` | Bounded by 512-byte line limit upstream | `GroupName::new()` called; validates RFC 3977 format (letter-first components, allowed chars, no empty components) | N/A (no SQL in handler) | Yes | No — type enforces format |
| STAT number argument | `stat_article()` | Bounded by 512-byte line limit | `s.parse::<u64>()` with `.ok()` — returns None on failure, handled gracefully | N/A | Yes | No |
| STAT message-id argument | `stat_article()` | Bounded by 512-byte line limit | Starts-with-`<` dispatch only; message-id not validated | N/A | Yes | Partial — no format check but only used for stub 430 response currently |

---

## Table 3 — LIST Command Handler

**File:** `crates/reader/src/session/commands/list.rs`

| Input | Source | Max Length | Format Check | SQL Safe | Shell Safe | Gap |
|-------|--------|-----------|-------------|---------|------------|-----|
| LIST ACTIVE wildmat pattern | `list_active()` via `matches_wildmat()` | No explicit limit | Wildmat matched character-by-character; no injection risk; recursive backtrack on `*` — no length cap | N/A | Yes | Yes — see Gap 4 (ReDoS via long `*` pattern) |
| LIST NEWSGROUPS wildmat pattern | `list_newsgroups()` via `matches_wildmat()` | No explicit limit | Same as above | N/A | Yes | Yes — see Gap 4 |
| NEWNEWS wildmat | `newnews()` | No explicit limit | Passed through without validation; v1 ignores it (returns empty) | N/A | Yes | Low risk in v1; Gap 4 applies when implemented |

---

## Table 4 — OVER/XOVER Handler

**File:** `crates/reader/src/session/commands/over.rs`

| Input | Source | Max Length | Format Check | SQL Safe | Shell Safe | Gap |
|-------|--------|-----------|-------------|---------|------------|-----|
| OVER range (passed as `ArticleRange`) | `over_response()` / `xover_response()` | Bounded by 512-byte line upstream | Range already parsed by `parse_range()`; handler receives typed `ArticleRange` enum; no re-parsing | Yes — range values are integers bound as SQL params in `OverviewStore::query_range()` | Yes | No |
| OVER article number | Same as above | Same | Same | Yes | Yes | No |

---

## Table 5 — POST Article Body

**Files:** `crates/reader/src/session/commands/post.rs`,
`crates/reader/src/post/validate_headers.rs`

| Input | Source | Max Length | Format Check | SQL Safe | Shell Safe | Gap |
|-------|--------|-----------|-------------|---------|------------|-----|
| POST article body (dot-terminated stream) | `read_dot_terminated()` | 1 MiB default checked in `complete_post()` after full read | Dot-unstuffing applied per RFC 5536; UTF-8 handling via `String::from_utf8_lossy` | N/A at read time | Yes | Yes — see Gap 6 (body read unbounded before size check) |
| POST header block (mandatory headers) | `complete_post()` / `validate_post_headers()` | 998 bytes per line enforced in `check_line_lengths()` | `From`, `Newsgroups`, `Date`, `Message-ID`, `Subject` all checked for presence and format | N/A | Yes | No |
| POST Newsgroups header values | `check_newsgroups()` in `validate_post_headers()` | Bounded by 998-byte line limit | Each group name parsed via `GroupName::new()`; additionally requires all-lowercase | N/A | Yes | No |
| POST Date header value | `check_date()` | Bounded by 998-byte line limit | Parsed by `mailparse::dateparse()`; checked within ±24 h of system clock | N/A | Yes | No |
| POST Message-ID header value | `check_message_id()` | Bounded by 998-byte line limit | `<local@domain>` with no whitespace or extra angle brackets; both parts non-empty | N/A | Yes | No |

---

## Table 6 — IHAVE / CHECK / TAKETHIS (Transit Ingestion)

**File:** `crates/transit/src/peering/ingestion.rs`

| Input | Source | Max Length | Format Check | SQL Safe | Shell Safe | Gap |
|-------|--------|-----------|-------------|---------|------------|-----|
| IHAVE/TAKETHIS message-id (command line) | `check_ingest()` → `validate_msgid_format()` | No explicit length limit | Checks `<`, `>`, `@` presence and `len() > 3`; weaker than reader-side check (no whitespace check, no empty-part check) | N/A | Yes | Yes — see Gap 7 |
| IHAVE/TAKETHIS article bytes | `check_ingest()` | 1 MiB (`MAX_ARTICLE_BYTES`) | Size checked before mandatory header scan; mandatory headers checked via `has_header()` (presence only) | N/A at validation stage; later storage uses parameterized queries | Yes | No |
| CHECK message-id | `check_ingest()` (same path) | Same as IHAVE | Same as IHAVE | N/A | Yes | Yes — see Gap 7 |

---

## Table 7 — SQLite Query Sites

**Files:** `crates/core/src/msgid_map.rs`,
`crates/reader/src/store/article_numbers.rs`,
`crates/reader/src/store/overview.rs`

| Input | Source | Max Length | Format Check | SQL Safe | Shell Safe | Gap |
|-------|--------|-----------|-------------|---------|------------|-----|
| Message-ID bound to SQL | `MsgIdMap::insert()`, `lookup_by_msgid()` | Not re-checked at SQL layer | Format checked upstream before reaching SQL | Yes — `sqlx::query_scalar("... WHERE message_id = ?").bind(message_id)` | Yes | No |
| CID bytes bound to SQL | All store methods | Fixed-length binary blob | CID is typed; `cid.to_bytes()` produces canonical bytes | Yes — bound as blob `?` | Yes | No |
| Group name bound to SQL | `ArticleNumberStore`, `OverviewStore` | Not re-checked at SQL layer | Checked by `GroupName::new()` upstream | Yes — `?` bind on all sites | Yes | No |
| Article number bound to SQL | `ArticleNumberStore::lookup_cid()` | u64 type | Parsed by `parse::<u64>()` upstream | Yes — bound as `i64` cast of u64 | Yes | No |
| OVER range (low, high) bound to SQL | `OverviewStore::query_range()` | u64 type | Parsed upstream; typed | Yes — bound as `i64` | Yes | No |

---

## Gaps Found

### Gap 1 — GROUP name not validated before dispatch stub sets state

**File:** `crates/reader/src/session/dispatch.rs`, lines 53–63

In the stub dispatcher, `Command::Group(name)` calls `GroupName::new(name).ok()`
and stores the result as `ctx.current_group`. If `GroupName::new()` fails, `ok()`
returns `None` and the group is silently set to `None`, but the dispatcher still
responds `211` (group selected) and sets state to `GroupSelected`. The group
state machine advances on an invalid or non-existent group name.

This is a dispatcher stub bug rather than a pure validation gap, but the
validation call is silent-on-failure in a way that masks the input error.

**Risk:** Low — the stub response is incorrect, not a security issue. However,
when real store logic is wired in, if the pattern of ignoring `GroupName::new()`
failures persists, the server could enter `GroupSelected` state with no group,
and subsequent ARTICLE/OVER commands would produce wrong results.

---

### Gap 2 — Message-ID not validated at parse time for ARTICLE/HEAD/BODY/STAT/IHAVE (reader side)

**File:** `crates/reader/src/session/command.rs`, `parse_article_ref()`, line 196

The function dispatches on `s.starts_with('<')` to classify a token as a
message-ID, but does no further validation. A malformed message-ID such as
`<no-at-sign>`, `< spaces@foo>`, or `<a@b@c>` is stored verbatim in the
`Command` enum and passed to the handler. The handler then looks it up in
storage — where the lookup returns `None` (correct), but the malformed string
was accepted and stored in the session state without error.

For IHAVE specifically, `parse_command()` stores the raw string in
`Command::Ihave(rest)` with no validation at all — no `<` check, no `@` check.
This means `IHAVE` with a completely arbitrary string (no angle brackets) is
parsed as a valid `Ihave` command variant and forwarded to the transit ingestion
path, which does apply `validate_msgid_format()`. The defense is present but
only at the second layer; the first layer is absent.

**Risk:** Low for current storage stub behavior. Medium when real storage is
wired in, because the unvalidated string reaches `MsgIdMap::lookup_by_msgid()`
as-is (though it is SQL-safe due to parameterized binding).

---

### Gap 3 — OVER/XOVER range parse silently coerces bad input to 0

**File:** `crates/reader/src/session/command.rs`, `parse_range()`, lines 203–216

When a range token cannot be parsed as a `u64`, `unwrap_or(0)` is used as the
fallback. For example, `OVER abc` produces `ArticleRange::Single(0)`, and
`OVER abc-xyz` produces `ArticleRange::Range(0, 0)`. Article number 0 is not
a valid RFC 3977 article number (numbers start at 1), so the query will return
no results — but the behavior is silent and may be confusing in logs.

RFC 3977 §6.2.4 says the server MUST return 423 ("No article with that number")
if the range is syntactically invalid. Returning an empty 224 response instead
is a protocol conformance error.

**Risk:** Low security risk. Medium conformance risk.

---

### Gap 4 — Wildmat pattern has no length limit; backtracking wildmat matcher

**File:** `crates/reader/src/session/commands/list.rs`, `wildmat_match()`,
lines 21–37

The recursive `wildmat_match()` function has O(2^n) worst-case behavior when
the pattern contains many consecutive `*` characters matched against a long
string. For example, `LIST ACTIVE *.*.*.*.*.*.*.*` against a list of 10,000
groups would perform exponential backtracking per group name.

The wildmat string is accepted from the client (bounded only by the 512-byte
command line limit) with no additional length check or character validation.

**Risk:** Medium. A single connection can cause CPU exhaustion with a carefully
constructed wildmat pattern. A memoized or iterative implementation would
eliminate this. The wildmat string is also never validated for illegal characters
(e.g. embedded NUL), though the command line limit makes this low severity.

---

### Gap 5 — NEWGROUPS and NEWNEWS date/time arguments not validated

**File:** `crates/reader/src/session/command.rs`, lines 123–152

The date and time tokens from `NEWGROUPS yyyymmdd hhmmss` and
`NEWNEWS wildmat yyyymmdd hhmmss` are captured as raw `String` fields with no
format validation. RFC 3977 §7.3 and §7.4 specify an 8-digit date (`yyyymmdd`)
and 6-digit time (`hhmmss`). Arbitrary strings are accepted and stored in the
`Command` enum.

The dispatch stub (in `dispatch.rs`) passes `since_timestamp: 0` to handlers,
ignoring the date/time entirely, so there is no immediate security impact. When
this is wired to real storage, the unvalidated date/time strings will reach the
business logic.

**Risk:** Low for v1 (behavior stubbed). Medium when implemented — parsing a
malformed date string at the business layer without upstream validation is
avoidable.

---

### Gap 6 — POST article body read into memory before size check

**File:** `crates/reader/src/session/commands/post.rs`, `read_dot_terminated()`,
lines 29–59; `complete_post()`, line 73

`read_dot_terminated()` reads the entire dot-terminated article stream into a
`Vec<u8>` without any size limit. The size check (`complete_post()`) is applied
only after the full article has been buffered. A malicious client can send an
arbitrarily large stream (terabytes, limited only by available memory) and
the server will buffer all of it before rejecting it.

The fix is to enforce the size limit incrementally inside `read_dot_terminated()`
by tracking accumulated byte count and aborting early.

**Risk:** High. This is a straightforward memory exhaustion denial-of-service
vector: one TCP connection can exhaust all available RAM on the server.

---

### Gap 7 — Transit-side `validate_msgid_format()` weaker than reader-side check

**File:** `crates/transit/src/peering/ingestion.rs`, `validate_msgid_format()`,
lines 142–153

The transit validator checks only: `len() > 3`, starts with `<`, ends with `>`,
contains `@`. It does not check:
- That `@` appears exactly once (multiple `@` accepted: `<a@b@c>`)
- That the local part before `@` is non-empty (`<@domain>` passes: starts with
  `<`, ends with `>`, contains `@`, `len() > 3`)
- That neither part contains whitespace

The reader-side validator in `crates/core/src/validation.rs`
(`is_valid_message_id()`) is stricter: it checks exactly one `@`, non-empty
local and domain parts, and no whitespace or embedded angle brackets. The
transit path should reuse the same validator.

**Risk:** Low for storage safety (SQL is parameterized). Medium for correctness:
a malformed message-ID that passes transit validation but fails reader validation
could be stored and then never be retrievable via the reader path.

---

## Items Verified Clean

The following were explicitly checked and found to have no gaps:

- **SQL injection:** All query sites in `msgid_map.rs`, `article_numbers.rs`,
  and `overview.rs` use `sqlx` parameterized binds exclusively. No
  `format!(...SELECT...)` or string-interpolated SQL found anywhere.
- **Shell injection:** No user input is passed to `std::process::Command`,
  `exec()`, or any shell at any point.
- **Group name type enforcement:** `GroupName::new()` enforces RFC 3977 format
  at construction time. The type system prevents an invalid `GroupName` from
  being stored in the `Newsgroups` header field — any group name that reaches
  the `ArticleHeader.newsgroups` field has been validated.
- **Article body size limit (IHAVE path):** Checked at the beginning of
  `check_ingest()` (step 3) before mandatory header scan — correct order.
- **Header field length (POST path):** `check_line_lengths()` enforces 998-byte
  limit per RFC 5322 before any header parsing.
- **Fuzz coverage:** `crates/core/fuzz/fuzz_targets/validate_ingress.rs`
  exercises `validate_article_ingress()` with arbitrary byte input; no panic
  paths found (by inspection of fuzz target structure).
- **Dot-stuffing/unstuffing:** Correctly implemented in both directions; applied
  at the right boundary (output: `fetch.rs`; input: `post.rs`).
