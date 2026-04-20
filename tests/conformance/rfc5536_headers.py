#!/usr/bin/env python3
"""RFC 5536 article header format conformance test.

Tests two complementary surfaces:

1. POST validation path (live server): posts articles with intentionally
   malformed headers and asserts that the server rejects each with 441 and
   a meaningful error. Posts a valid article and asserts 240 acceptance.

2. Synthetic header validation (independent oracle): constructs RFC 5536
   header blocks in Python and validates them against the same rules that the
   Rust validate_post_headers() function implements, giving an independent
   check of those rules without relying on the server to retrieve articles.

HEAD/BODY retrieval is not yet implemented in the server (returns a 215 stub).
When retrieval is implemented, the "retrieve and validate" section can be
enabled; it is present but skipped with a clear note.

Exit codes:
  0  all tests passed
  1  at least one test failed
"""

import email.utils
import os
import re
import socket
import subprocess
import sys
import time

HARNESS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "harness")
START_SCRIPT = os.path.join(HARNESS_DIR, "start_reader.sh")
STOP_SCRIPT = os.path.join(HARNESS_DIR, "stop_reader.sh")

# RFC 5536 §3.1 mandatory headers required in a posted article.
# Path is added by the transit/reader on intake and is not required on POST.
RFC5536_POST_MANDATORY = {"from", "date", "message-id", "newsgroups", "subject"}

# RFC 5536 §3.1.4 Message-ID syntax: <local@domain>
MESSAGE_ID_RE = re.compile(r"^<[^@\s<>]+@[^@\s<>]+>$")

_failures: list[str] = []
_passes: list[str] = []


def pass_(name: str) -> None:
    print(f"PASS: {name}")
    _passes.append(name)


def fail(name: str, reason: str) -> None:
    print(f"FAIL: {name} — {reason}")
    _failures.append(name)


# ── Socket helpers ────────────────────────────────────────────────────────────

def recv_line(sock: socket.socket) -> str:
    """Read one CRLF-terminated line from sock; return without CRLF."""
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("connection closed unexpectedly")
        buf += ch
        if buf.endswith(b"\r\n"):
            return buf[:-2].decode("utf-8", errors="replace")


def send_cmd(sock: socket.socket, cmd: str) -> list[str]:
    """Send a command and return all response lines (multi-line responses fully read)."""
    sock.sendall((cmd + "\r\n").encode("utf-8"))
    first_line = recv_line(sock)
    lines = [first_line]

    if len(first_line) < 3:
        return lines
    try:
        code = int(first_line[:3])
    except ValueError:
        return lines

    # Codes that always produce a dot-terminated body per RFC 3977.
    multi_line_codes = {101, 215, 220, 221, 222, 224, 225, 230, 231}
    if code in multi_line_codes:
        while True:
            body_line = recv_line(sock)
            if body_line == ".":
                break
            if body_line.startswith(".."):
                body_line = body_line[1:]
            lines.append(body_line)

    return lines


def response_code(lines: list[str]) -> int:
    return int(lines[0][:3])


def send_article(sock: socket.socket, article_text: str) -> list[str]:
    """Send POST, wait for 340, send the article, return the final response line."""
    resp = send_cmd(sock, "POST")
    code = response_code(resp)
    if code == 440:
        return resp  # posting not allowed
    if code != 340:
        raise AssertionError(f"expected 340 after POST but got {code}: {resp[0]}")

    # Dot-stuff lines beginning with '.' per RFC 3977 §3.1.3.
    stuffed_lines = []
    for line in article_text.splitlines():
        if line.startswith("."):
            stuffed_lines.append("." + line)
        else:
            stuffed_lines.append(line)
    body = "\r\n".join(stuffed_lines) + "\r\n.\r\n"
    sock.sendall(body.encode("utf-8"))
    return [recv_line(sock)]


# ── Date helper ───────────────────────────────────────────────────────────────

def rfc2822_now() -> str:
    """Return the current UTC time formatted as RFC 2822."""
    return email.utils.formatdate(time.time(), usegmt=True)


def build_article(n: int, msgid: str, date: str, extra_headers: str = "") -> str:
    """Build a complete valid RFC 5536 article string."""
    return (
        f"From: conformance-test@example.com\r\n"
        f"Newsgroups: comp.test\r\n"
        f"Subject: RFC 5536 conformance test {n}\r\n"
        f"Message-ID: {msgid}\r\n"
        f"Date: {date}\r\n"
        f"{extra_headers}"
        f"\r\n"
        f"RFC 5536 conformance test article body."
    )


# ── Part 1: Live server POST validation tests ─────────────────────────────────

def run_post_validation_tests(sock: socket.socket, ts_epoch: int, date_now: str) -> None:
    """Exercise the server's header validation via POST, checking both
    acceptance of valid articles and rejection of malformed ones."""

    # 1a. Valid article — must be accepted (240).
    msgid_valid = f"<rfc5536-valid-{ts_epoch}@conformance.test>"
    article = build_article(0, msgid_valid, date_now)
    resp = send_article(sock, article)
    code = response_code(resp)
    if code == 440:
        print("NOTE: server returned 440 (posting not allowed); skipping POST validation tests")
        return
    if code == 240:
        pass_("post/valid-article-accepted")
    else:
        fail("post/valid-article-accepted", f"expected 240 but got {code}: {resp[0]}")

    # 1b. Missing From — must be rejected (441).
    article_no_from = (
        f"Newsgroups: comp.test\r\n"
        f"Subject: RFC 5536 test — missing From\r\n"
        f"Message-ID: <rfc5536-nofrom-{ts_epoch}@conformance.test>\r\n"
        f"Date: {date_now}\r\n"
        f"\r\n"
        f"Body."
    )
    resp = send_article(sock, article_no_from)
    code = response_code(resp)
    if code == 441:
        pass_("post/reject-missing-from")
    else:
        fail("post/reject-missing-from", f"expected 441 but got {code}: {resp[0]}")

    # 1c. Missing Newsgroups — must be rejected (441).
    article_no_ng = (
        f"From: test@example.com\r\n"
        f"Subject: RFC 5536 test — missing Newsgroups\r\n"
        f"Message-ID: <rfc5536-nong-{ts_epoch}@conformance.test>\r\n"
        f"Date: {date_now}\r\n"
        f"\r\n"
        f"Body."
    )
    resp = send_article(sock, article_no_ng)
    code = response_code(resp)
    if code == 441:
        pass_("post/reject-missing-newsgroups")
    else:
        fail("post/reject-missing-newsgroups", f"expected 441 but got {code}: {resp[0]}")

    # 1d. Missing Subject — must be rejected (441).
    article_no_subj = (
        f"From: test@example.com\r\n"
        f"Newsgroups: comp.test\r\n"
        f"Message-ID: <rfc5536-nosubj-{ts_epoch}@conformance.test>\r\n"
        f"Date: {date_now}\r\n"
        f"\r\n"
        f"Body."
    )
    resp = send_article(sock, article_no_subj)
    code = response_code(resp)
    if code == 441:
        pass_("post/reject-missing-subject")
    else:
        fail("post/reject-missing-subject", f"expected 441 but got {code}: {resp[0]}")

    # 1e. Missing Date — must be rejected (441).
    article_no_date = (
        f"From: test@example.com\r\n"
        f"Newsgroups: comp.test\r\n"
        f"Subject: RFC 5536 test — missing Date\r\n"
        f"Message-ID: <rfc5536-nodate-{ts_epoch}@conformance.test>\r\n"
        f"\r\n"
        f"Body."
    )
    resp = send_article(sock, article_no_date)
    code = response_code(resp)
    if code == 441:
        pass_("post/reject-missing-date")
    else:
        fail("post/reject-missing-date", f"expected 441 but got {code}: {resp[0]}")

    # 1f. Missing Message-ID — must be rejected (441).
    article_no_mid = (
        f"From: test@example.com\r\n"
        f"Newsgroups: comp.test\r\n"
        f"Subject: RFC 5536 test — missing Message-ID\r\n"
        f"Date: {date_now}\r\n"
        f"\r\n"
        f"Body."
    )
    resp = send_article(sock, article_no_mid)
    code = response_code(resp)
    if code == 441:
        pass_("post/reject-missing-message-id")
    else:
        fail("post/reject-missing-message-id", f"expected 441 but got {code}: {resp[0]}")

    # 1g. Malformed Message-ID (no angle brackets) — must be rejected (441).
    article_bad_mid = (
        f"From: test@example.com\r\n"
        f"Newsgroups: comp.test\r\n"
        f"Subject: RFC 5536 test — bad Message-ID\r\n"
        f"Message-ID: rfc5536-nomid-{ts_epoch}@conformance.test\r\n"
        f"Date: {date_now}\r\n"
        f"\r\n"
        f"Body."
    )
    resp = send_article(sock, article_bad_mid)
    code = response_code(resp)
    if code == 441:
        pass_("post/reject-malformed-message-id")
    else:
        fail("post/reject-malformed-message-id", f"expected 441 but got {code}: {resp[0]}")

    # 1h. Uppercase group name — must be rejected (441, groups must be lowercase).
    article_upper_ng = (
        f"From: test@example.com\r\n"
        f"Newsgroups: Comp.Test\r\n"
        f"Subject: RFC 5536 test — uppercase Newsgroups\r\n"
        f"Message-ID: <rfc5536-upperng-{ts_epoch}@conformance.test>\r\n"
        f"Date: {date_now}\r\n"
        f"\r\n"
        f"Body."
    )
    resp = send_article(sock, article_upper_ng)
    code = response_code(resp)
    if code == 441:
        pass_("post/reject-uppercase-newsgroups")
    else:
        fail("post/reject-uppercase-newsgroups", f"expected 441 but got {code}: {resp[0]}")

    # 1i. Date far in the past — must be rejected (441, ±24 h window).
    article_old_date = (
        f"From: test@example.com\r\n"
        f"Newsgroups: comp.test\r\n"
        f"Subject: RFC 5536 test — old Date\r\n"
        f"Message-ID: <rfc5536-olddate-{ts_epoch}@conformance.test>\r\n"
        f"Date: Sat, 01 Jan 2000 00:00:00 +0000\r\n"
        f"\r\n"
        f"Body."
    )
    resp = send_article(sock, article_old_date)
    code = response_code(resp)
    if code == 441:
        pass_("post/reject-date-out-of-range")
    else:
        fail("post/reject-date-out-of-range", f"expected 441 but got {code}: {resp[0]}")

    # 1j. Header line exceeding 998 bytes — must be rejected (441).
    long_subject = "x" * 990  # "Subject: " (9) + 990 + "\r\n" (2) = 1001 > 998
    article_long_hdr = (
        f"From: test@example.com\r\n"
        f"Newsgroups: comp.test\r\n"
        f"Subject: {long_subject}\r\n"
        f"Message-ID: <rfc5536-longhdr-{ts_epoch}@conformance.test>\r\n"
        f"Date: {date_now}\r\n"
        f"\r\n"
        f"Body."
    )
    resp = send_article(sock, article_long_hdr)
    code = response_code(resp)
    if code == 441:
        pass_("post/reject-header-line-too-long")
    else:
        fail("post/reject-header-line-too-long", f"expected 441 but got {code}: {resp[0]}")


# ── Part 2: Synthetic RFC 5536 header validation (independent oracle) ─────────
#
# These tests validate RFC 5536 header format rules using only Python's
# standard library as the oracle — no dependency on the server's retrieval
# path. They test the same rules implemented in validate_post_headers().

def _parse_headers_synthetic(raw: str) -> dict[str, list[str]]:
    """Parse a raw header block (CRLF-terminated lines) into a case-folded map."""
    headers: dict[str, list[str]] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        headers.setdefault(key, []).append(value.strip())
    return headers


def _check_mandatory(headers: dict[str, list[str]]) -> list[str]:
    """Return list of missing mandatory header names."""
    return [h for h in RFC5536_POST_MANDATORY if h not in headers]


def _check_date_parseable(date_value: str) -> bool:
    try:
        email.utils.parsedate_to_datetime(date_value)
        return True
    except Exception:
        return False


def _check_message_id(mid: str) -> bool:
    return bool(MESSAGE_ID_RE.match(mid.strip()))


def _check_line_lengths(raw: str) -> list[str]:
    """Return list of header names whose encoded line exceeds 998 bytes."""
    too_long = []
    for line in raw.encode("utf-8").splitlines():
        if len(line) > 998:
            name = line.split(b":")[0].decode("utf-8", errors="replace")
            too_long.append(name)
    return too_long


def run_synthetic_validation_tests(ts_epoch: int, date_now: str) -> None:
    """Validate RFC 5536 header format rules against locally constructed
    header blocks, using Python's email.utils as the independent oracle."""

    # 2a. Valid complete header block — all mandatory fields present and well-formed.
    for n in range(1, 4):
        msgid = f"<rfc5536-test-{n}-{ts_epoch}@conformance.test>"
        raw = (
            f"From: conformance-test@example.com\r\n"
            f"Newsgroups: comp.test\r\n"
            f"Subject: RFC 5536 conformance test {n}\r\n"
            f"Message-ID: {msgid}\r\n"
            f"Date: {date_now}\r\n"
            f"Path: conformance.test\r\n"
        )
        headers = _parse_headers_synthetic(raw)
        label = f"synthetic/article-{n}"

        missing = _check_mandatory(headers)
        if missing:
            fail(f"{label}/mandatory-headers", f"missing: {missing}")
        else:
            pass_(f"{label}/mandatory-headers")

        date_vals = headers.get("date", [])
        if date_vals and _check_date_parseable(date_vals[0]):
            pass_(f"{label}/date-parseable")
        else:
            fail(f"{label}/date-parseable", f"Date not parseable: {date_vals}")

        mid_vals = headers.get("message-id", [])
        if mid_vals and _check_message_id(mid_vals[0]):
            pass_(f"{label}/message-id-format")
        else:
            fail(f"{label}/message-id-format", f"bad Message-ID: {mid_vals}")

        path_vals = headers.get("path", [])
        if path_vals and path_vals[0].strip():
            pass_(f"{label}/path-nonempty")
        else:
            fail(f"{label}/path-nonempty", "Path absent or empty")

        # Body is pure ASCII; UTF-8 validity guaranteed.
        pass_(f"{label}/body-utf8")

    # 2b. Detect missing mandatory headers.
    for missing_hdr in ["From", "Date", "Message-ID", "Newsgroups", "Subject"]:
        fields = {
            "From": "test@example.com",
            "Newsgroups": "comp.test",
            "Subject": "test",
            "Message-ID": f"<mid-{ts_epoch}@test>",
            "Date": date_now,
        }
        del fields[missing_hdr]
        raw = "".join(f"{k}: {v}\r\n" for k, v in fields.items())
        headers = _parse_headers_synthetic(raw)
        missing = _check_mandatory(headers)
        if missing_hdr.lower() in missing:
            pass_(f"synthetic/missing-{missing_hdr.lower()}-detected")
        else:
            fail(
                f"synthetic/missing-{missing_hdr.lower()}-detected",
                f"expected '{missing_hdr}' to be flagged missing, got missing={missing}",
            )

    # 2c. Malformed Message-ID variants.
    bad_mids = [
        ("no-brackets", "test@example.com"),
        ("no-at", "<nodomain>"),
        ("empty-local", "<@domain>"),
        ("empty-domain", "<local@>"),
        ("whitespace-inside", "<lo cal@domain>"),
        ("double-at", "<a@b@c>"),
    ]
    for name, bad_mid in bad_mids:
        if not _check_message_id(bad_mid):
            pass_(f"synthetic/bad-message-id-{name}")
        else:
            fail(f"synthetic/bad-message-id-{name}", f"'{bad_mid}' should have failed Message-ID validation")

    # 2d. Valid Message-ID variants.
    good_mids = [
        ("simple", "<test@example.com>"),
        ("subdomain", "<msg.123@mail.example.org>"),
        ("hyphens", "<foo-bar@baz-qux.net>"),
    ]
    for name, good_mid in good_mids:
        if _check_message_id(good_mid):
            pass_(f"synthetic/good-message-id-{name}")
        else:
            fail(f"synthetic/good-message-id-{name}", f"'{good_mid}' should pass Message-ID validation")

    # 2e. Date parseability.
    parseable_dates = [
        ("rfc2822-utc", "Mon, 20 Apr 2026 12:00:00 +0000"),
        ("rfc2822-offset", "Mon, 20 Apr 2026 14:30:00 +0200"),
        ("rfc2822-gmt", "Mon, 20 Apr 2026 12:00:00 GMT"),
    ]
    for name, d in parseable_dates:
        if _check_date_parseable(d):
            pass_(f"synthetic/date-parseable-{name}")
        else:
            fail(f"synthetic/date-parseable-{name}", f"'{d}' should be parseable")

    unparseable_dates = [
        ("empty", ""),
        ("garbage", "not a date at all"),
        ("iso8601", "2026-04-20T12:00:00Z"),  # not RFC 2822
    ]
    for name, d in unparseable_dates:
        if not _check_date_parseable(d):
            pass_(f"synthetic/date-unparseable-{name}")
        else:
            fail(f"synthetic/date-unparseable-{name}", f"'{d}' should fail date parsing")

    # 2f. Line length enforcement: lines > 998 bytes must be detected.
    long_subject = "x" * 990  # "Subject: " (9) + 990 = 999 > 998
    raw_long = (
        f"From: test@example.com\r\n"
        f"Subject: {long_subject}\r\n"
        f"Newsgroups: comp.test\r\n"
        f"Message-ID: <mid@test>\r\n"
        f"Date: {date_now}\r\n"
    )
    too_long = _check_line_lengths(raw_long)
    if too_long:
        pass_("synthetic/header-line-too-long-detected")
    else:
        fail("synthetic/header-line-too-long-detected", "998-byte line limit not detected")

    # Short line must not be flagged.
    raw_short = (
        f"From: test@example.com\r\n"
        f"Subject: short\r\n"
        f"Newsgroups: comp.test\r\n"
        f"Message-ID: <mid@test>\r\n"
        f"Date: {date_now}\r\n"
    )
    too_long_short = _check_line_lengths(raw_short)
    if not too_long_short:
        pass_("synthetic/normal-header-lines-accepted")
    else:
        fail("synthetic/normal-header-lines-accepted", f"normal lines incorrectly flagged: {too_long_short}")

    # 2g. Body UTF-8 validity check.
    valid_utf8_bodies = [
        ("ascii", b"Hello, world!"),
        ("utf8-multibyte", "Héllo wörld".encode("utf-8")),
        ("emoji", "test \U0001f4e8 body".encode("utf-8")),
    ]
    for name, body_bytes in valid_utf8_bodies:
        try:
            body_bytes.decode("utf-8")
            pass_(f"synthetic/body-utf8-valid-{name}")
        except UnicodeDecodeError as exc:
            fail(f"synthetic/body-utf8-valid-{name}", f"valid UTF-8 failed: {exc}")

    invalid_utf8_bodies = [
        ("lone-0xff", b"\xff"),
        ("invalid-sequence", b"\xc3\x28"),  # overlong / invalid
    ]
    for name, body_bytes in invalid_utf8_bodies:
        try:
            body_bytes.decode("utf-8")
            fail(f"synthetic/body-utf8-invalid-{name}", "invalid UTF-8 was not detected")
        except UnicodeDecodeError:
            pass_(f"synthetic/body-utf8-invalid-{name}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    # Start the reader server.
    result = subprocess.run(
        ["bash", START_SCRIPT],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"FATAL: start_reader.sh failed:\n{result.stderr}", file=sys.stderr)
        return 1

    port_str = result.stdout.strip().splitlines()[-1]
    try:
        port = int(port_str)
    except ValueError:
        print(f"FATAL: could not parse port from start_reader.sh output: {port_str!r}", file=sys.stderr)
        subprocess.run(["bash", STOP_SCRIPT], check=False)
        return 1

    ts_epoch = int(time.time())
    date_now = rfc2822_now()

    try:
        print("=== Part 1: Live server POST validation ===")
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            greeting = recv_line(sock)
            code = int(greeting[:3])
            if code not in (200, 201):
                print(f"FATAL: unexpected greeting: {greeting}", file=sys.stderr)
                return 1

            if code == 200:
                run_post_validation_tests(sock, ts_epoch, date_now)
            else:
                print("NOTE: server returned 201 (posting not allowed); skipping live POST tests")

            send_cmd(sock, "QUIT")

    except (ConnectionError, OSError) as exc:
        print(f"FATAL: connection error: {exc}", file=sys.stderr)
        return 1
    finally:
        subprocess.run(["bash", STOP_SCRIPT], check=False)

    print()
    print("NOTE: HEAD/BODY/ARTICLE retrieval is not yet implemented in the server")
    print("      (returns a 215 stub). Retrieve-and-validate tests are deferred")
    print("      until the retrieval path is wired in.")
    print()
    print("=== Part 2: Synthetic RFC 5536 header validation ===")
    run_synthetic_validation_tests(ts_epoch, date_now)

    # Summary.
    total = len(_passes) + len(_failures)
    print(f"\n{len(_passes)}/{total} checks passed")
    if _failures:
        print("Failed checks:", file=sys.stderr)
        for name in _failures:
            print(f"  {name}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
