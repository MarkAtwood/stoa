#!/usr/bin/env python3
"""Headless NNTP protocol driver for integration testing.

Usage: python3 nntp_driver.py <port>

Connects to 127.0.0.1:<port> and runs a canned NNTP command sequence,
asserting RFC 3977 response codes at each step.

Exit codes:
  0  all assertions passed
  1  assertion failure or connection error
"""

import socket
import sys


def recv_line(sock: socket.socket) -> str:
    """Read bytes from sock one byte at a time until CRLF, return the line without CRLF."""
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("connection closed unexpectedly")
        buf += ch
        if buf.endswith(b"\r\n"):
            return buf[:-2].decode("utf-8", errors="replace")


def send_cmd(sock: socket.socket, cmd: str) -> list[str]:
    """Send a command (CRLF appended) and return the full response as a list of lines.

    For multi-line responses (initial code 1xx, 2xx, 3xx where RFC 3977 defines
    a body), reads until a bare '.' terminator line. For single-line responses,
    returns a one-element list.
    """
    sock.sendall((cmd + "\r\n").encode("utf-8"))
    first_line = recv_line(sock)
    lines = [first_line]

    if not first_line or len(first_line) < 3:
        return lines

    try:
        code = int(first_line[:3])
    except ValueError:
        return lines

    # RFC 3977 multi-line responses end with a dot-terminated body.
    # Codes that always have a multi-line body per RFC 3977:
    #   101 (CAPABILITIES), 215 (LIST), 220 (ARTICLE), 221 (HEAD),
    #   222 (BODY), 224 (OVER), 225 (HDR), 230 (NEWNEWS), 231 (NEWGROUPS)
    multi_line_codes = {101, 215, 220, 221, 222, 224, 225, 230, 231}
    if code in multi_line_codes:
        while True:
            body_line = recv_line(sock)
            if body_line == ".":
                break
            # Dot-stuffed lines: leading dot is removed per RFC 3977 §3.1.3
            if body_line.startswith(".."):
                body_line = body_line[1:]
            lines.append(body_line)

    return lines


def assert_code(response: list[str], expected_code: int) -> None:
    """Raise AssertionError if the response does not begin with expected_code."""
    if not response:
        raise AssertionError(f"expected {expected_code} but got empty response")
    first = response[0]
    try:
        actual = int(first[:3])
    except (ValueError, IndexError):
        raise AssertionError(
            f"expected {expected_code} but could not parse code from: {first!r}"
        )
    if actual != expected_code:
        raise AssertionError(
            f"expected {expected_code} but got {actual}: {first!r}"
        )


def run_tests(port: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        # Step 1: Read greeting (200 or 201)
        greeting_line = recv_line(sock)
        if not greeting_line:
            raise AssertionError("expected greeting but got empty response")
        try:
            code = int(greeting_line[:3])
        except (ValueError, IndexError):
            raise AssertionError(f"could not parse greeting code from: {greeting_line!r}")
        if code not in (200, 201):
            raise AssertionError(
                f"expected greeting 200 or 201 but got {code}: {greeting_line!r}"
            )
        print(f"  greeting: {greeting_line}")

        # Step 2: CAPABILITIES -> 101
        resp = send_cmd(sock, "CAPABILITIES")
        assert_code(resp, 101)
        print(f"  CAPABILITIES: {resp[0]}")

        # Step 3: MODE READER -> 200 or 201
        resp = send_cmd(sock, "MODE READER")
        try:
            code = int(resp[0][:3])
        except (ValueError, IndexError):
            raise AssertionError(f"could not parse MODE READER response: {resp[0]!r}")
        if code not in (200, 201):
            raise AssertionError(
                f"expected MODE READER 200 or 201 but got {code}: {resp[0]!r}"
            )
        print(f"  MODE READER: {resp[0]}")

        # Step 4: LIST ACTIVE -> 215
        resp = send_cmd(sock, "LIST ACTIVE")
        assert_code(resp, 215)
        print(f"  LIST ACTIVE: {resp[0]}")

        # Step 5: QUIT -> 205
        resp = send_cmd(sock, "QUIT")
        assert_code(resp, 205)
        print(f"  QUIT: {resp[0]}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <port>", file=sys.stderr)
        return 1

    try:
        port = int(sys.argv[1])
    except ValueError:
        print(f"error: port must be an integer, got: {sys.argv[1]!r}", file=sys.stderr)
        return 1

    try:
        run_tests(port)
    except AssertionError as exc:
        print(f"FAIL: assertion error: {exc}", file=sys.stderr)
        return 1
    except (ConnectionError, OSError) as exc:
        print(f"FAIL: connection error: {exc}", file=sys.stderr)
        return 1

    print("PASS: all assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
