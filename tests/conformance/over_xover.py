#!/usr/bin/env python3
"""OVER / XOVER conformance test — RFC 3977 §8.3 and RFC 6048 §2.

This script tests OVER and XOVER behaviour that is fully deterministic on a
fresh (empty) server, i.e. conditions that require no articles to be present.

Run via the harness:

    PORT=$(tests/harness/start_reader.sh)
    python3 tests/conformance/over_xover.py "$PORT"
    tests/harness/stop_reader.sh

Or directly against a running server:

    python3 tests/conformance/over_xover.py <port>

Exit codes:
  0  all tests passed
  1  one or more tests failed

--- Future extension: OVER with actual articles ---

When article ingestion is implemented, add tests that:
  1. POST or IHAVE one or more articles into a group.
  2. SELECT the group with GROUP <name>.
  3. Send OVER <lo>-<hi> covering the ingested range.
  4. Assert 224 response with the correct number of tab-separated lines.
  5. Validate each line has exactly 8 tab-separated fields in the order
     defined by LIST OVERVIEW.FMT: number, Subject, From, Date, Message-ID,
     References, :bytes, :lines.
  6. Cross-check the Message-ID field against the value returned by the
     ARTICLE command for each article number.
  7. Verify XOVER returns identical output to OVER for the same range
     (XOVER is a legacy alias: RFC 3977 §8.3.1 Note 2).
  8. Test OVER with a single article number (no dash).
  9. Test OVER with an open range (n- syntax) at the top of the group.
 10. Test OVER with a range that falls entirely outside the group's article
     numbers; expect 224 with an empty body (RFC 3977 §8.3.2 says the server
     MAY return 420 or 423 instead — accept either 224 with empty body or 420/423).
"""

import socket
import sys


def recv_line(sock: socket.socket) -> str:
    """Read one CRLF-terminated line, return it without the CRLF."""
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("connection closed unexpectedly")
        buf += ch
        if buf.endswith(b"\r\n"):
            return buf[:-2].decode("utf-8", errors="replace")


def send_cmd(sock: socket.socket, cmd: str) -> list[str]:
    """Send command, return response lines (dot-termination consumed for multiline codes)."""
    sock.sendall((cmd + "\r\n").encode("utf-8"))
    first = recv_line(sock)
    lines = [first]

    if not first or len(first) < 3:
        return lines
    try:
        code = int(first[:3])
    except ValueError:
        return lines

    # Codes that always carry a dot-terminated body per RFC 3977.
    multi_line_codes = {101, 215, 220, 221, 222, 224, 225, 230, 231}
    if code in multi_line_codes:
        while True:
            body_line = recv_line(sock)
            if body_line == ".":
                break
            # Dot-stuffed lines: remove the leading dot per RFC 3977 §3.1.3.
            if body_line.startswith(".."):
                body_line = body_line[1:]
            lines.append(body_line)

    return lines


def assert_code(resp: list[str], expected: int, context: str) -> None:
    """Raise AssertionError if the response code is not `expected`."""
    if not resp:
        raise AssertionError(f"{context}: expected {expected} but got empty response")
    try:
        actual = int(resp[0][:3])
    except (ValueError, IndexError):
        raise AssertionError(
            f"{context}: expected {expected} but could not parse code from {resp[0]!r}"
        )
    if actual != expected:
        raise AssertionError(
            f"{context}: expected {expected} but got {actual}: {resp[0]!r}"
        )


def run_tests(port: int) -> int:
    """Run all OVER/XOVER conformance tests. Returns 0 on full pass, 1 on any failure."""
    failures: list[str] = []

    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        # Consume greeting (200 or 201).
        greeting = recv_line(sock)
        try:
            greeting_code = int(greeting[:3])
        except (ValueError, IndexError):
            failures.append(f"greeting: could not parse code from {greeting!r}")
            return 1
        if greeting_code not in (200, 201):
            failures.append(f"greeting: expected 200 or 201, got {greeting_code}: {greeting!r}")
            return 1

        # ------------------------------------------------------------------
        # Test 1: OVER with no group selected must return 412.
        #
        # RFC 3977 §8.3.1:
        #   "If no group has been indicated, a 412 response MUST be returned."
        # ------------------------------------------------------------------
        test_name = "OVER_no_group_412"
        try:
            resp = send_cmd(sock, "OVER")
            assert_code(resp, 412, test_name)
            print(f"PASS: {test_name}")
        except AssertionError as exc:
            print(f"FAIL: {test_name}: {exc}")
            failures.append(test_name)

        # ------------------------------------------------------------------
        # Test 2: XOVER with no group selected must return 412.
        #
        # RFC 3977 §8.3.1 Note 2: XOVER is a deprecated synonym for OVER
        # and MUST behave identically, including error responses.
        # ------------------------------------------------------------------
        test_name = "XOVER_no_group_412"
        try:
            resp = send_cmd(sock, "XOVER")
            assert_code(resp, 412, test_name)
            print(f"PASS: {test_name}")
        except AssertionError as exc:
            print(f"FAIL: {test_name}: {exc}")
            failures.append(test_name)

        # ------------------------------------------------------------------
        # Test 3: OVER <range> with no group selected must also return 412.
        #
        # RFC 3977 §8.3.1: the range form also requires a selected group.
        # ------------------------------------------------------------------
        test_name = "OVER_range_no_group_412"
        try:
            resp = send_cmd(sock, "OVER 1-10")
            assert_code(resp, 412, test_name)
            print(f"PASS: {test_name}")
        except AssertionError as exc:
            print(f"FAIL: {test_name}: {exc}")
            failures.append(test_name)

        # ------------------------------------------------------------------
        # Test 4: XOVER <range> with no group selected must return 412.
        # ------------------------------------------------------------------
        test_name = "XOVER_range_no_group_412"
        try:
            resp = send_cmd(sock, "XOVER 1-10")
            assert_code(resp, 412, test_name)
            print(f"PASS: {test_name}")
        except AssertionError as exc:
            print(f"FAIL: {test_name}: {exc}")
            failures.append(test_name)

        # ------------------------------------------------------------------
        # Test 5: LIST OVERVIEW.FMT — 215 response with required fields.
        #
        # RFC 6048 §2.1 mandates this fixed field order:
        #   Subject:, From:, Date:, Message-ID:, References:, :bytes, :lines
        #
        # The colon suffix on header names (e.g. "Subject:") means the value
        # is taken from the named header.  The colon prefix on ":bytes" and
        # ":lines" means they are computed metadata, not headers.
        # ------------------------------------------------------------------
        test_name = "LIST_OVERVIEW_FMT_215"
        try:
            resp = send_cmd(sock, "LIST OVERVIEW.FMT")
            assert_code(resp, 215, test_name)
            body = resp[1:]  # lines after the status line

            required_fields = [
                "Subject:",
                "From:",
                "Date:",
                "Message-ID:",
                "References:",
                ":bytes",
                ":lines",
            ]
            for field in required_fields:
                if not any(line.strip() == field for line in body):
                    raise AssertionError(
                        f"LIST OVERVIEW.FMT body missing required field {field!r}; "
                        f"got: {body!r}"
                    )

            print(f"PASS: {test_name}")
        except AssertionError as exc:
            print(f"FAIL: {test_name}: {exc}")
            failures.append(test_name)

        # ------------------------------------------------------------------
        # Test 6: CAPABILITIES advertises OVER.
        #
        # RFC 3977 §8.3.1: if the server implements OVER/XOVER it MUST
        # include "OVER" in its CAPABILITIES response.
        # ------------------------------------------------------------------
        test_name = "CAPABILITIES_advertises_OVER"
        try:
            resp = send_cmd(sock, "CAPABILITIES")
            assert_code(resp, 101, test_name)
            caps_body = resp[1:]
            if not any(line.strip() == "OVER" for line in caps_body):
                raise AssertionError(
                    f"CAPABILITIES did not include 'OVER'; caps body: {caps_body!r}"
                )
            print(f"PASS: {test_name}")
        except AssertionError as exc:
            print(f"FAIL: {test_name}: {exc}")
            failures.append(test_name)

        # ------------------------------------------------------------------
        # Graceful close.
        # ------------------------------------------------------------------
        send_cmd(sock, "QUIT")

    if failures:
        print(f"\nFAILED: {len(failures)} test(s): {', '.join(failures)}")
        return 1

    print(f"\nAll {6} tests passed.")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <port>", file=sys.stderr)
        return 1
    try:
        port = int(sys.argv[1])
    except ValueError:
        print(f"error: port must be an integer, got {sys.argv[1]!r}", file=sys.stderr)
        return 1
    return run_tests(port)


if __name__ == "__main__":
    sys.exit(main())
