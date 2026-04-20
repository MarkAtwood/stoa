#!/usr/bin/env python3
"""RFC 3977 fetch-command conformance test.

Starts usenet-ipfs-reader, connects (one connection per test), and verifies
that fetch commands (ARTICLE, HEAD, BODY, STAT) and group commands (LIST
ACTIVE, GROUP) return the correct RFC 3977 response codes against an empty
store.

Exit codes:
  0  all assertions passed
  1  one or more assertions failed (FAIL lines printed to stdout)
"""

import os
import socket
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HARNESS_DIR = os.path.join(SCRIPT_DIR, "..", "harness")
START_SCRIPT = os.path.join(HARNESS_DIR, "start_reader.sh")
STOP_SCRIPT = os.path.join(HARNESS_DIR, "stop_reader.sh")

# Per-socket read timeout (seconds).
SOCK_TIMEOUT = 5

# RFC 3977 codes that carry a dot-terminated multi-line body.
MULTI_LINE_CODES = {101, 215, 220, 221, 222, 224, 225, 230, 231}


def recv_line(sock: socket.socket) -> str:
    """Read one CRLF-terminated line from sock; return it without the CRLF."""
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("connection closed unexpectedly")
        buf += ch
        if buf.endswith(b"\r\n"):
            return buf[:-2].decode("utf-8", errors="replace")


def recv_first_line(sock: socket.socket) -> str:
    """Read exactly one line (CRLF-terminated) and return it without CRLF."""
    return recv_line(sock)


def send_cmd_single_line(sock: socket.socket, cmd: str) -> list[str]:
    """Send cmd and return only the first response line (no body drain).

    Use this when the expected response code is NOT in MULTI_LINE_CODES,
    to avoid blocking on a body that may or may not be sent.
    """
    sock.sendall((cmd + "\r\n").encode("utf-8"))
    first_line = recv_first_line(sock)
    return [first_line]


def send_cmd_multiline(sock: socket.socket, cmd: str) -> list[str]:
    """Send cmd and read the full multi-line body until a bare '.' line.

    Use only when the expected response code IS in MULTI_LINE_CODES.
    """
    sock.sendall((cmd + "\r\n").encode("utf-8"))
    first_line = recv_first_line(sock)
    lines = [first_line]

    if not first_line or len(first_line) < 3:
        return lines

    try:
        code = int(first_line[:3])
    except ValueError:
        return lines

    if code in MULTI_LINE_CODES:
        while True:
            body_line = recv_line(sock)
            if body_line == ".":
                break
            lines.append(body_line)

    return lines


def fresh_session(port: int) -> socket.socket:
    """Open a new connection, consume the greeting, return the socket.

    Raises ConnectionError if the greeting is not 200 or 201.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=SOCK_TIMEOUT)
    sock.settimeout(SOCK_TIMEOUT)
    greeting = recv_first_line(sock)
    code = int(greeting[:3])
    if code not in (200, 201):
        sock.close()
        raise ConnectionError(f"unexpected greeting {code}: {greeting!r}")
    return sock


def actual_code(response: list[str]) -> int:
    """Return the integer response code from the first line."""
    return int(response[0][:3])


def run_one_test(port: int, cmd: str, expected: int, rfc_note: str) -> str:
    """Run a single command test in its own connection.

    For commands whose RFC-correct response is in MULTI_LINE_CODES, drain the
    body.  For all others, read only the first line to avoid blocking on a
    misbehaving server that sends a multi-line code without a body terminator.

    Returns a 'PASS: ...' or 'FAIL: ...' string.
    """
    test_name = cmd.replace(" ", "_").replace("<", "").replace(">", "").replace("@", "_at_")
    label = f"{test_name}_returns_{expected}"

    try:
        with fresh_session(port) as sock:
            if expected in MULTI_LINE_CODES:
                resp = send_cmd_multiline(sock, cmd)
            else:
                resp = send_cmd_single_line(sock, cmd)
            got = actual_code(resp)
    except OSError as exc:
        return f"FAIL: {label} — connection error: {exc} [{rfc_note}]"

    if got == expected:
        return f"PASS: {label}"
    return (
        f"FAIL: {label} expected {expected} got {got}: {resp[0]!r}"
        f" [{rfc_note}]"
    )


def run_tests(port: int) -> list[str]:
    """Run all conformance tests; return a list of 'PASS:' or 'FAIL:' lines."""
    results = []

    # 1. LIST ACTIVE with empty store -> 215 + dot-terminated empty list.
    results.append(run_one_test(
        port,
        "LIST ACTIVE",
        215,
        "RFC 3977 §7.6.3: LIST ACTIVE must return 215 with dot-terminated body",
    ))

    # 2. GROUP on a non-existent group -> 411 (RFC 3977 §6.1.1).
    results.append(run_one_test(
        port,
        "GROUP no.such.group.xyzzy",
        411,
        "RFC 3977 §6.1.1: unknown group must return 411",
    ))

    # 3. ARTICLE <number> with no group selected -> 412 (RFC 3977 §6.2.1).
    results.append(run_one_test(
        port,
        "ARTICLE 1",
        412,
        "RFC 3977 §6.2.1: number form without group selected must return 412",
    ))

    # 4. ARTICLE <msgid> not in store -> 430 (RFC 3977 §6.2.1).
    results.append(run_one_test(
        port,
        "ARTICLE <nonexistent-msgid@example.com>",
        430,
        "RFC 3977 §6.2.1: unknown message-id must return 430",
    ))

    # 5. HEAD <msgid> not in store -> 430 (RFC 3977 §6.2.2).
    results.append(run_one_test(
        port,
        "HEAD <nonexistent-msgid@example.com>",
        430,
        "RFC 3977 §6.2.2: unknown message-id must return 430",
    ))

    # 6. BODY <msgid> not in store -> 430 (RFC 3977 §6.2.3).
    results.append(run_one_test(
        port,
        "BODY <nonexistent-msgid@example.com>",
        430,
        "RFC 3977 §6.2.3: unknown message-id must return 430",
    ))

    # 7. STAT <msgid> not in store -> 430 (RFC 3977 §6.2.4).
    results.append(run_one_test(
        port,
        "STAT <nonexistent-msgid@example.com>",
        430,
        "RFC 3977 §6.2.4: unknown message-id must return 430",
    ))

    return results


def main() -> int:
    # Start the reader.
    try:
        result = subprocess.run(
            ["bash", START_SCRIPT],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"FAIL: could not start reader: {exc.stderr.strip()}", file=sys.stderr)
        return 1

    port_str = result.stdout.strip()
    try:
        port = int(port_str)
    except ValueError:
        print(
            f"FAIL: start_reader.sh returned non-integer port: {port_str!r}",
            file=sys.stderr,
        )
        return 1

    failures = 0
    try:
        results = run_tests(port)
    finally:
        subprocess.run(["bash", STOP_SCRIPT], capture_output=True)

    for line in results:
        print(line)
        if line.startswith("FAIL:"):
            failures += 1

    if failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
