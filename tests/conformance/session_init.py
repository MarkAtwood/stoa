#!/usr/bin/env python3
"""RFC 3977 session-initialisation conformance test.

Starts the reader via tests/harness/start_reader.sh, runs four tests against
a live TCP connection, then tears down the server via stop_reader.sh.

Exit codes:
  0  all tests passed
  1  at least one test failed
"""

import atexit
import os
import socket
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HARNESS_DIR = os.path.join(SCRIPT_DIR, "..", "harness")
START_SH = os.path.join(HARNESS_DIR, "start_reader.sh")
STOP_SH = os.path.join(HARNESS_DIR, "stop_reader.sh")

_PASS = 0
_FAIL = 0


def _stop_reader() -> None:
    subprocess.run(["bash", STOP_SH], check=False)


def _start_reader() -> int:
    """Start the reader; return the port it is listening on."""
    result = subprocess.run(
        ["bash", START_SH],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr, end="")
        raise RuntimeError(f"start_reader.sh failed (exit {result.returncode})")
    port_str = result.stdout.strip()
    try:
        return int(port_str)
    except ValueError:
        raise RuntimeError(
            f"start_reader.sh did not print a port number; got: {port_str!r}"
        )


def _recv_line(sock: socket.socket) -> str:
    """Read bytes one at a time until CRLF; return line without CRLF."""
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("connection closed unexpectedly")
        buf += ch
        if buf.endswith(b"\r\n"):
            return buf[:-2].decode("utf-8", errors="replace")


def _send_cmd(sock: socket.socket, cmd: str) -> list[str]:
    """Send a command (CRLF appended); return full response as list of lines.

    Multi-line response bodies (code 101) are read until the bare-dot
    terminator and returned as additional list elements (dot-stuffing removed).
    """
    sock.sendall((cmd + "\r\n").encode("utf-8"))
    first_line = _recv_line(sock)
    lines = [first_line]

    if len(first_line) < 3:
        return lines

    try:
        code = int(first_line[:3])
    except ValueError:
        return lines

    # Only 101 (CAPABILITIES) is exercised here; handle it explicitly.
    if code == 101:
        while True:
            body_line = _recv_line(sock)
            if body_line == ".":
                break
            if body_line.startswith(".."):
                body_line = body_line[1:]
            lines.append(body_line)

    return lines


def _pass(name: str) -> None:
    global _PASS
    _PASS += 1
    print(f"PASS: {name}")


def _fail(name: str, reason: str) -> None:
    global _FAIL
    _FAIL += 1
    print(f"FAIL: {name}: {reason}")


def run_tests(port: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:

        # ------------------------------------------------------------------ #
        # Test 1: Greeting                                                    #
        # RFC 3977 §5.1: server sends 200 (posting allowed) or 201 (read-    #
        # only) on connect.  The harness config has auth.required=false and   #
        # the server always starts with posting_allowed=true, so 200 is       #
        # expected.                                                           #
        # ------------------------------------------------------------------ #
        try:
            greeting = _recv_line(sock)
            if not greeting.startswith("200 ") and not greeting.startswith("201 "):
                _fail(
                    "greeting",
                    f"expected line starting with '200 ' or '201 '; got {greeting!r}",
                )
            else:
                _pass("greeting")
        except Exception as exc:
            _fail("greeting", str(exc))
            return  # No point continuing if we cannot even connect.

        # ------------------------------------------------------------------ #
        # Test 2: CAPABILITIES                                                #
        # RFC 3977 §5.2: response code 101, body includes "VERSION 2".       #
        # ------------------------------------------------------------------ #
        try:
            resp = _send_cmd(sock, "CAPABILITIES")
            first = resp[0]
            if not first.startswith("101"):
                _fail("capabilities_code", f"expected 101; got {first!r}")
            else:
                _pass("capabilities_code")
                if "VERSION 2" in resp[1:]:
                    _pass("capabilities_version_2")
                else:
                    _fail(
                        "capabilities_version_2",
                        f"'VERSION 2' not found in body; body lines: {resp[1:]!r}",
                    )
        except Exception as exc:
            _fail("capabilities_code", str(exc))
            _fail("capabilities_version_2", "skipped due to earlier failure")

        # ------------------------------------------------------------------ #
        # Test 3: MODE READER                                                 #
        # RFC 3977 §5.3: returns 200 (posting allowed) or 201 (read-only).   #
        # The server starts with posting_allowed=true, so 200 is expected.    #
        # ------------------------------------------------------------------ #
        try:
            resp = _send_cmd(sock, "MODE READER")
            first = resp[0]
            if not first.startswith("200 "):
                _fail(
                    "mode_reader",
                    f"expected line starting with '200 '; got {first!r}",
                )
            else:
                _pass("mode_reader")
        except Exception as exc:
            _fail("mode_reader", str(exc))

        # ------------------------------------------------------------------ #
        # Test 4: QUIT                                                        #
        # RFC 3977 §5.4: response code 205.                                  #
        # ------------------------------------------------------------------ #
        try:
            resp = _send_cmd(sock, "QUIT")
            first = resp[0]
            if not first.startswith("205 "):
                _fail("quit", f"expected line starting with '205 '; got {first!r}")
            else:
                _pass("quit")
        except Exception as exc:
            _fail("quit", str(exc))


def main() -> int:
    atexit.register(_stop_reader)

    try:
        port = _start_reader()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    run_tests(port)

    total = _PASS + _FAIL
    if _FAIL == 0:
        print(f"All {total} tests passed")
        return 0
    else:
        print(f"{_FAIL} of {total} tests FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
