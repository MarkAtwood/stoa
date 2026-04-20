# NNTP Test Harness

Headless integration test harness for `usenet-ipfs-reader`. Starts the reader
binary against a minimal config, drives a canned NNTP command sequence over raw
TCP, asserts RFC 3977 response codes, and tears down the process on exit.

## Dependencies

- `python3` (3.6+, stdlib only — no third-party packages required)
- `nc` (netcat, used by `start_reader.sh` to poll for port readiness)
- `usenet-ipfs-reader` binary: `cargo build -p usenet-ipfs-reader`

slrn / tin / pan are not required for this harness. RFC 3977 conformance tests
driven by real newsreader clients are a separate concern.

## Running

```
cd tests/harness
bash run_harness.sh
```

Or with an explicit port:

```
PORT=$(./start_reader.sh 15100)
python3 nntp_driver.py "$PORT"
./stop_reader.sh
```

## Test sequence

`nntp_driver.py` runs the following in a single TCP connection:

1. Read greeting — asserts 200 or 201
2. `CAPABILITIES` — asserts 101
3. `MODE READER` — asserts 200 or 201
4. `LIST ACTIVE` — asserts 215
5. `QUIT` — asserts 205

## Extending

To add a new test step, add a `send_cmd` + `assert_code` call inside
`run_tests()` in `nntp_driver.py` before the `QUIT` command. The driver handles
multi-line responses automatically for the standard RFC 3977 multi-line codes
(101, 215, 220, 221, 222, 224, 225, 230, 231).

## Files

| File | Purpose |
|---|---|
| `run_harness.sh` | Master script: starts reader, runs driver, cleans up |
| `start_reader.sh` | Starts `usenet-ipfs-reader` with a temp config; prints port |
| `stop_reader.sh` | Kills the reader process and removes the temp config dir |
| `nntp_driver.py` | Raw-socket NNTP driver; run independently with `python3 nntp_driver.py <port>` |
