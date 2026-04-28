-- Persist the HLC clock state across restarts to preserve monotonicity
-- (usenet-ipfs-gq0z).
--
-- A single row (id=1) stores the last emitted HLC timestamp.  On startup,
-- this row is loaded and used to seed HlcClock::new_seeded so that the
-- first send() after restart is strictly greater than any previously emitted
-- timestamp, even after NTP clock steps or restarts within the same
-- millisecond.
--
-- Updated by a background task every 30 seconds; also updated on graceful
-- shutdown.  A missed save means the clock reverts to wall-clock time on
-- restart, which is safe unless the restart happens within the same
-- millisecond as the last emit — an unlikely but theoretically possible
-- monotonicity violation.
CREATE TABLE IF NOT EXISTS hlc_checkpoint (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    wall_ms  BIGINT  NOT NULL,
    logical  BIGINT  NOT NULL,
    saved_at BIGINT  NOT NULL
);
