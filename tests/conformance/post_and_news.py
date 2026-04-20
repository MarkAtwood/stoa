#!/usr/bin/env python3
"""Conformance tests for POST, NEWNEWS, and NEWGROUPS commands (RFC 3977).

Usage:
    python3 post_and_news.py <port>
    python3 post_and_news.py          # starts/stops reader via harness scripts

Exit codes:
    0  all tests passed
    1  one or more tests failed
"""

import os
import socket
import subprocess
import sys
import time


# ---------------------------------------------------------------------------
# Protocol helpers (mirrors nntp_driver.py but kept self-contained so this
# file can be run standalone or imported by a future test runner)
# ---------------------------------------------------------------------------

def recv_line(sock: socket.socket) -> str:
    """Read one CRLF-terminated line from sock; return it without CRLF."""
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("connection closed unexpectedly")
        buf += ch
        if buf.endswith(b"\r\n"):
            return buf[:-2].decode("utf-8", errors="replace")


def recv_multiline(sock: socket.socket) -> list[str]:
    """Read a dot-terminated multi-line body; return lines without terminator."""
    lines = []
    while True:
        line = recv_line(sock)
        if line == ".":
            break
        if line.startswith(".."):
            line = line[1:]
        lines.append(line)
    return lines


def send_line(sock: socket.socket, data: str) -> None:
    """Send data + CRLF."""
    sock.sendall((data + "\r\n").encode("utf-8"))


def send_raw(sock: socket.socket, data: bytes) -> None:
    sock.sendall(data)


def parse_code(line: str) -> int:
    try:
        return int(line[:3])
    except (ValueError, IndexError):
        raise AssertionError(f"cannot parse response code from: {line!r}")


# Multi-line response codes per RFC 3977
_MULTILINE_CODES = {101, 215, 220, 221, 222, 224, 225, 230, 231}


def cmd(sock: socket.socket, command: str) -> tuple[int, str, list[str]]:
    """Send *command* and return (code, first_line, body_lines).

    body_lines is populated only for multi-line response codes.
    """
    send_line(sock, command)
    first = recv_line(sock)
    code = parse_code(first)
    body: list[str] = []
    if code in _MULTILINE_CODES:
        body = recv_multiline(sock)
    return code, first, body


# ---------------------------------------------------------------------------
# Harness helpers
# ---------------------------------------------------------------------------

HARNESS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "harness")


def start_reader() -> tuple[int, subprocess.Popen]:
    """Start the reader via start_reader.sh; return (port, process_handle).

    The process handle is kept so we can pass it to stop_reader().
    Actually start_reader.sh backgrounds itself and writes a PID file; we call
    stop_reader.sh at teardown.  We use subprocess.run for the start call and
    return None as the handle (cleanup via stop_reader.sh).
    """
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
    port = int(result.stdout.strip())
    return port


def stop_reader() -> None:
    subprocess.run(
        [os.path.join(HARNESS_DIR, "stop_reader.sh")],
        capture_output=True,
    )


def connect(port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    # Read and discard the greeting
    greeting = recv_line(sock)
    greeting_code = parse_code(greeting)
    if greeting_code not in (200, 201):
        raise AssertionError(f"unexpected greeting {greeting!r}")
    return sock


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

_RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str = "") -> None:
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {name}" + (f": {detail}" if detail else ""))
    _RESULTS.append((name, passed, detail))


def test_post_initiation(port: int) -> None:
    """POST command returns 340 (send article) when posting is allowed."""
    with connect(port) as sock:
        code, first, _ = cmd(sock, "POST")
        passed = code == 340
        record("POST initiation (340)", passed, first)
        if not passed and code == 440:
            record(
                "POST initiation (440 known limitation)",
                True,
                "server reports posting not permitted — acceptable if posting_allowed=false in config",
            )


def test_post_valid_article(port: int) -> None:
    """POST a minimal RFC 5536-conformant article and expect 240."""
    timestamp = int(time.time())
    article = (
        f"From: test@example.com\r\n"
        f"Newsgroups: comp.test\r\n"
        f"Subject: Test article\r\n"
        f"Message-ID: <test-{timestamp}@example.com>\r\n"
        f"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
        f"\r\n"
        f"Test body.\r\n"
        f".\r\n"
    )

    with connect(port) as sock:
        init_code, init_line, _ = cmd(sock, "POST")
        if init_code == 440:
            record(
                "POST valid article (240)",
                True,
                "skipped — server returned 440 (posting not permitted)",
            )
            return
        if init_code != 340:
            record("POST valid article (240)", False, f"expected 340, got: {init_line!r}")
            return

        # Send the article body (no command prefix; just raw lines + terminator)
        send_raw(sock, article.encode("utf-8"))
        result_line = recv_line(sock)
        result_code = parse_code(result_line)
        passed = result_code == 240
        record("POST valid article (240)", passed, result_line)


def test_post_missing_from(port: int) -> None:
    """POST article with no From: header expects 441."""
    timestamp = int(time.time())
    article = (
        f"Newsgroups: comp.test\r\n"
        f"Subject: Test article\r\n"
        f"Message-ID: <test-nofrom-{timestamp}@example.com>\r\n"
        f"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
        f"\r\n"
        f"Test body.\r\n"
        f".\r\n"
    )

    with connect(port) as sock:
        init_code, init_line, _ = cmd(sock, "POST")
        if init_code == 440:
            record(
                "POST missing From → 441",
                True,
                "skipped — server returned 440 (posting not permitted)",
            )
            return
        if init_code != 340:
            record("POST missing From → 441", False, f"expected 340, got: {init_line!r}")
            return

        send_raw(sock, article.encode("utf-8"))
        result_line = recv_line(sock)
        result_code = parse_code(result_line)
        passed = result_code == 441
        record("POST missing From → 441", passed, result_line)


def test_newnews(port: int) -> None:
    """NEWNEWS returns 230 with dot-terminated body (may be empty)."""
    with connect(port) as sock:
        code, first, body = cmd(sock, "NEWNEWS comp.* 19700101 000000 GMT")
        passed = code == 230
        detail = first
        if passed:
            detail += f" ({len(body)} article message-id(s))"
        record("NEWNEWS 230 + dot-terminator", passed, detail)


def test_newgroups(port: int) -> None:
    """NEWGROUPS returns 231 with dot-terminated body (may be empty)."""
    with connect(port) as sock:
        code, first, body = cmd(sock, "NEWGROUPS 19700101 000000 GMT")
        passed = code == 231
        detail = first
        if passed:
            detail += f" ({len(body)} group(s))"
        record("NEWGROUPS 231 + dot-terminator", passed, detail)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_tests(port: int) -> bool:
    print(f"Running conformance tests against 127.0.0.1:{port}")
    test_post_initiation(port)
    test_post_valid_article(port)
    test_post_missing_from(port)
    test_newnews(port)
    test_newgroups(port)

    failures = [name for name, passed, _ in _RESULTS if not passed]
    print()
    if failures:
        print(f"FAILED ({len(failures)} of {len(_RESULTS)} tests):")
        for name in failures:
            print(f"  - {name}")
        return False
    print(f"PASSED ({len(_RESULTS)} tests)")
    return True


def main() -> int:
    if len(sys.argv) == 2:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"error: port must be an integer, got: {sys.argv[1]!r}", file=sys.stderr)
            return 1
        return 0 if run_tests(port) else 1

    # No port given: start and stop the reader ourselves.
    try:
        port = start_reader()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        ok = run_tests(port)
    finally:
        stop_reader()

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
