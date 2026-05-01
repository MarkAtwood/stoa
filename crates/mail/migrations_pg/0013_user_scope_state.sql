-- Migration 0013 (Postgres): add user_id to state_version and jmap_change_log.
--
-- Existing rows (all owned by user_id=1 in single-user v1) are preserved.

ALTER TABLE state_version ADD COLUMN user_id BIGINT NOT NULL DEFAULT 1;
ALTER TABLE state_version DROP CONSTRAINT state_version_pkey;
ALTER TABLE state_version ADD PRIMARY KEY (user_id, scope);

ALTER TABLE jmap_change_log ADD COLUMN user_id BIGINT NOT NULL DEFAULT 1;
ALTER TABLE jmap_change_log DROP CONSTRAINT jmap_change_log_pkey;
ALTER TABLE jmap_change_log ADD PRIMARY KEY (user_id, seq, scope, item_id);
