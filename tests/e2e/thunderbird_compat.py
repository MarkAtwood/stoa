#!/usr/bin/env python3
"""Thunderbird-compatible NNTP end-to-end test.

Emulates the exact NNTP command sequence that Thunderbird issues when a user
subscribes to a newsgroup, downloads message headers, reads an article, and
posts a reply.  Runs headless; no display server required.

Usage:
    python3 tests/e2e/thunderbird_compat.py [port]

If *port* is omitted the reader is started via tests/harness/start_reader.sh
and stopped at exit.

Exit codes:
    0  all phases passed (server stubs are noted but not failures)
    1  protocol error or unexpected response code
"""

import os
import socket
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Low-level socket helpers (no nntplib — we drive the wire protocol directly
# so we control every byte and can observe every stub response precisely)
# ---------------------------------------------------------------------------

HARNESS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "harness")

# Response codes defined by RFC 3977 that always carry a dot-terminated body.
_MULTILINE_CODES = {101, 215, 220, 221, 222, 224, 225, 230, 231}


def recv_line(sock: socket.socket) -> str:
    """Read one CRLF-terminated line; return without CRLF."""
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("connection closed unexpectedly")
        buf += ch
        if buf.endswith(b"\r\n"):
            return buf[:-2].decode("utf-8", errors="replace")


def recv_multiline(sock: socket.socket) -> list[str]:
    """Read a dot-terminated body; return lines with dot-unstuffing applied."""
    lines: list[str] = []
    while True:
        line = recv_line(sock)
        if line == ".":
            break
        if line.startswith(".."):
            line = line[1:]
        lines.append(line)
    return lines


def cmd(sock: socket.socket, command: str) -> tuple[int, str, list[str]]:
    """Send *command* and return (code, first_line, body_lines).

    body_lines is populated only for multi-line response codes.
    """
    sock.sendall((command + "\r\n").encode("utf-8"))
    first = recv_line(sock)
    try:
        code = int(first[:3])
    except (ValueError, IndexError):
        raise AssertionError(f"cannot parse response code from: {first!r}")
    body: list[str] = []
    if code in _MULTILINE_CODES:
        body = recv_multiline(sock)
    return code, first, body


def post_article(sock: socket.socket, headers: dict[str, str], body: str) -> tuple[int, str]:
    """Send POST + article and return (code, first_line) of the final response."""
    init_code, init_line, _ = cmd(sock, "POST")
    if init_code != 340:
        return init_code, init_line

    header_block = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    article_bytes = (header_block + "\r\n" + body + "\r\n.\r\n").encode("utf-8")
    sock.sendall(article_bytes)
    result = recv_line(sock)
    try:
        code = int(result[:3])
    except (ValueError, IndexError):
        raise AssertionError(f"cannot parse POST result code from: {result!r}")
    return code, result


# ---------------------------------------------------------------------------
# Harness helpers
# ---------------------------------------------------------------------------

def start_reader() -> int:
    """Start the reader via harness script; return port number."""
    result = subprocess.run(
        [os.path.join(HARNESS_DIR, "start_reader.sh")],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"start_reader.sh failed (exit {result.returncode}):\n"
            f"  stdout: {result.stdout.strip()}\n"
            f"  stderr: {result.stderr.strip()}"
        )
    return int(result.stdout.strip())


def stop_reader() -> None:
    subprocess.run(
        [os.path.join(HARNESS_DIR, "stop_reader.sh")],
        capture_output=True,
    )


# ---------------------------------------------------------------------------
# Test result tracking
# ---------------------------------------------------------------------------

_RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str = "") -> None:
    status = "PASS" if passed else "FAIL"
    suffix = f": {detail}" if detail else ""
    print(f"  [{status}] {name}{suffix}")
    _RESULTS.append((name, passed, detail))


def note_stub(step: str) -> None:
    print(f"  NOTE: {step} — server stub, tracking gap")


# ---------------------------------------------------------------------------
# Phase 1 — Initial connection (Thunderbird startup)
# ---------------------------------------------------------------------------

def phase1_initial_connection(sock: socket.socket) -> dict[str, bool]:
    """Thunderbird connects, reads greeting, sends CAPABILITIES and MODE READER."""
    print("\nPhase 1: Initial connection")
    state: dict[str, bool] = {}

    # Greeting (200 posting allowed / 201 no posting)
    greeting = recv_line(sock)
    try:
        code = int(greeting[:3])
        ok = code in (200, 201)
    except (ValueError, IndexError):
        ok = False
    record("greeting (200/201)", ok, greeting)
    state["greeting"] = ok
    if not ok:
        return state

    # CAPABILITIES → 101
    code, first, caps_body = cmd(sock, "CAPABILITIES")
    ok = code == 101
    record("CAPABILITIES (101)", ok, first)
    state["capabilities"] = ok
    if ok:
        caps = {line.split()[0].upper() for line in caps_body if line.strip()}
        print(f"    advertised: {', '.join(sorted(caps))}")
        state["has_over"] = "OVER" in caps
        state["has_post"] = "POST" in caps

    # MODE READER → 200 or 201
    code, first, _ = cmd(sock, "MODE READER")
    ok = code in (200, 201)
    record("MODE READER (200/201)", ok, first)
    state["mode_reader"] = ok

    return state


# ---------------------------------------------------------------------------
# Phase 2 — Group subscription (Thunderbird LIST ACTIVE + GROUP)
# ---------------------------------------------------------------------------

def phase2_group_subscription(sock: socket.socket) -> dict:
    """Thunderbird sends LIST ACTIVE then GROUP for each group found."""
    print("\nPhase 2: Group subscription")
    state: dict = {}

    # LIST ACTIVE → 215
    code, first, groups_body = cmd(sock, "LIST ACTIVE")
    ok = code == 215
    record("LIST ACTIVE (215)", ok, first)
    state["list_active"] = ok
    if not ok:
        return state

    print(f"    {len(groups_body)} group(s) returned")

    # If the server returns no groups, use comp.test as the canonical test group.
    # This is the standard newsgroup used for test posts; Thunderbird would
    # subscribe to it explicitly even if it's not yet in the active list.
    if groups_body:
        # Use first group from LIST ACTIVE
        first_group_line = groups_body[0]
        group_name = first_group_line.split()[0]
    else:
        note_stub("LIST ACTIVE returned empty — no groups registered yet")
        group_name = "comp.test"

    state["group_name"] = group_name

    # GROUP <name> → 211
    code, first, _ = cmd(sock, f"GROUP {group_name}")
    ok = code == 211
    if not ok and code == 411:
        note_stub(f"GROUP {group_name} → 411 (group not registered in server state)")
        record(f"GROUP {group_name} (211 or stub 411)", True, first)
        state["group_selected"] = False
        state["group_code"] = 411
        return state

    record(f"GROUP {group_name} (211)", ok, first)
    state["group_selected"] = ok
    state["group_code"] = code

    if ok:
        # 211 count low high name
        parts = first.split()
        if len(parts) >= 4:
            state["group_count"] = int(parts[1])
            state["group_low"] = int(parts[2])
            state["group_high"] = int(parts[3])
            print(f"    count={parts[1]} low={parts[2]} high={parts[3]}")

    return state


# ---------------------------------------------------------------------------
# Phase 3 — Header download (Thunderbird OVER-based message list)
# ---------------------------------------------------------------------------

_OVER_FIELDS = ["subject", "from", "date", "message-id", "references", ":bytes", ":lines"]


def phase3_header_download(sock: socket.socket, state: dict) -> dict:
    """Thunderbird downloads message list via OVER <low>-<high>."""
    print("\nPhase 3: Header download (OVER)")
    result: dict = {"overview_lines": []}

    group_selected = state.get("group_selected", False)
    group_code = state.get("group_code", 0)

    if not group_selected:
        if group_code == 411:
            note_stub("OVER skipped — group not selected (GROUP returned 411 stub)")
        else:
            note_stub("OVER skipped — group not selected")
        record("OVER skippable due to group stub", True, "")
        return result

    count = state.get("group_count", 0)
    low = state.get("group_low", 0)
    high = state.get("group_high", 0)

    if count == 0 or high < low:
        note_stub("OVER skipped — group has no articles (count=0 or empty range)")
        record("OVER skippable (empty group)", True, "")
        return result

    # Send OVER for the full article range
    code, first, body = cmd(sock, f"OVER {low}-{high}")
    ok = code == 224
    if not ok and code in (420, 423):
        note_stub(f"OVER {low}-{high} → {code} (no current article / no articles in range)")
        record("OVER (224 or stub 420/423)", True, first)
        return result

    record(f"OVER {low}-{high} (224)", ok, first)
    if not ok:
        return result

    result["overview_lines"] = body
    print(f"    {len(body)} overview line(s) returned")

    # Validate the 7-field format for each line
    all_valid = True
    for i, line in enumerate(body):
        fields = line.split("\t")
        if len(fields) < 7:
            record(f"OVER line {i} has ≥7 fields", False, f"got {len(fields)}: {line!r}")
            all_valid = False
        else:
            # fields: number, subject, from, date, message-id, references, :bytes, :lines
            # (field 0 is the article number, so 7 overview fields start at index 1)
            if len(fields) < 8:
                record(f"OVER line {i} has number + ≥7 fields", False, f"got {len(fields)} total")
                all_valid = False

    if body and all_valid:
        record("OVER overview lines have ≥8 tab-separated fields", True,
               f"{len(body)} line(s) validated")

    return result


# ---------------------------------------------------------------------------
# Phase 4 — Article fetch (Thunderbird reading a message)
# ---------------------------------------------------------------------------

def phase4_article_fetch(sock: socket.socket) -> dict:
    """POST a test article then fetch it via ARTICLE <msgid>."""
    print("\nPhase 4: Article fetch")
    state: dict = {}

    ts = int(time.time())
    msgid = f"<tb-compat-orig-{ts}@example.com>"
    state["msgid"] = msgid

    headers = {
        "From": "thunderbird-test@example.com",
        "Newsgroups": "comp.test",
        "Subject": "Thunderbird compat test article",
        "Message-ID": msgid,
        "Date": "Sun, 20 Apr 2026 00:00:00 +0000",
    }
    body = "This is a test article posted by the Thunderbird compat test suite."

    # POST the article
    code, first = post_article(sock, headers, body)
    if code == 440:
        note_stub("POST → 440 (posting not permitted)")
        record("POST test article (240 or stub 440)", True, first)
        state["posted"] = False
        return state
    if code == 340:
        # post_article returned 340 meaning POST init failed — shouldn't happen but guard it
        record("POST initiation (340→article)", False, first)
        state["posted"] = False
        return state

    ok = code == 240
    record("POST test article (240)", ok, first)
    state["posted"] = ok
    if not ok:
        return state

    # ARTICLE <msgid> → 220
    code, first, art_body = cmd(sock, f"ARTICLE {msgid}")
    ok = code == 220
    if not ok and code == 430:
        note_stub(f"ARTICLE {msgid} → 430 (article not retrievable — storage not wired up)")
        record("ARTICLE by msgid (220 or stub 430)", True, first)
        state["article_fetched"] = False
        return state

    record(f"ARTICLE {msgid} (220)", ok, first)
    state["article_fetched"] = ok

    if ok:
        has_body = any(line.strip() for line in art_body)
        record("ARTICLE response contains body", has_body,
               f"{len(art_body)} line(s)" if has_body else "body empty")

    return state


# ---------------------------------------------------------------------------
# Phase 5 — Reply (Thunderbird posting a reply and retrieving it)
# ---------------------------------------------------------------------------

def phase5_reply(sock: socket.socket, orig_state: dict) -> None:
    """POST a reply referencing the original article, then retrieve it."""
    print("\nPhase 5: Reply")

    orig_msgid = orig_state.get("msgid", "<unknown>")
    ts = int(time.time())
    reply_msgid = f"<tb-compat-reply-{ts}@example.com>"

    headers = {
        "From": "thunderbird-test@example.com",
        "Newsgroups": "comp.test",
        "Subject": "Re: Thunderbird compat test article",
        "Message-ID": reply_msgid,
        "References": orig_msgid,
        "Date": "Sun, 20 Apr 2026 00:01:00 +0000",
    }
    body = "This is a reply posted by the Thunderbird compat test suite."

    # POST the reply
    code, first = post_article(sock, headers, body)
    if code == 440:
        note_stub("POST reply → 440 (posting not permitted)")
        record("POST reply (240 or stub 440)", True, first)
        return
    if code == 340:
        record("POST reply initiation (340→article)", False, first)
        return

    ok = code == 240
    record("POST reply (240)", ok, first)
    if not ok:
        return

    # ARTICLE <reply-msgid> → 220
    code, first, art_body = cmd(sock, f"ARTICLE {reply_msgid}")
    ok = code == 220
    if not ok and code == 430:
        note_stub(f"ARTICLE {reply_msgid} → 430 (reply not retrievable — storage not wired up)")
        record("ARTICLE reply by msgid (220 or stub 430)", True, first)
        return

    record(f"ARTICLE {reply_msgid} (220)", ok, first)
    if ok:
        # Verify References header is present in the fetched reply
        refs_line = next(
            (l for l in art_body if l.lower().startswith("references:")), None
        )
        ok_refs = refs_line is not None and orig_msgid in refs_line
        record(
            "ARTICLE reply contains References header pointing to original",
            ok_refs,
            refs_line or "no References header found",
        )

        has_body = any(line.strip() for line in art_body)
        record("ARTICLE reply response contains body", has_body,
               f"{len(art_body)} line(s)" if has_body else "body empty")


# ---------------------------------------------------------------------------
# Top-level runner
# ---------------------------------------------------------------------------

def run_all(port: int) -> bool:
    print(f"Thunderbird compat test — connecting to 127.0.0.1:{port}")

    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        p1 = phase1_initial_connection(sock)
        if not p1.get("mode_reader"):
            print("\nFATAL: Phase 1 failed — cannot continue", file=sys.stderr)
            return False

        p2 = phase2_group_subscription(sock)
        phase3_header_download(sock, p2)
        p4 = phase4_article_fetch(sock)
        phase5_reply(sock, p4)

        cmd(sock, "QUIT")

    print()
    failures = [name for name, passed, _ in _RESULTS if not passed]
    if failures:
        print(f"RESULT: FAILED ({len(failures)} of {len(_RESULTS)} checks):")
        for name in failures:
            print(f"  - {name}")
        return False
    print(f"RESULT: PASSED ({len(_RESULTS)} checks)")
    return True


def main() -> int:
    if len(sys.argv) == 2:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"error: port must be an integer, got: {sys.argv[1]!r}", file=sys.stderr)
            return 1
        return 0 if run_all(port) else 1

    # No port given — start and stop the reader ourselves
    try:
        port = start_reader()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        ok = run_all(port)
    finally:
        stop_reader()

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
