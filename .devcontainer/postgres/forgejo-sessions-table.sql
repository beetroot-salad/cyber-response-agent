-- Forgejo's session table in `forgejo_sessions` (#1592 PP-5), included by `forgejo-sessions.sql` after it connects
-- there. Plain SQL, run as a superuser; the roles `fs_owner`, `fs_forgejo` and `fs_lifecycle` must exist. It may be
-- run again.
--
-- Forgejo's `[session] PROVIDER=postgres` reads and writes `key`, `data` and `expiry`; its INSERT names its columns, so
-- `signed_in_at` starts NULL. A sign-in re-keys the session's row (`UPDATE session SET key = ...`), and the trigger
-- stamps `signed_in_at` then and only then: the lifecycle ends sessions by it (a product sign-out, the one-hour cap).
CREATE TABLE IF NOT EXISTS session (
    key CHAR(16) PRIMARY KEY,
    data BYTEA,
    expiry INTEGER NOT NULL,
    signed_in_at TIMESTAMPTZ NULL
);
ALTER TABLE session OWNER TO fs_owner;

CREATE OR REPLACE FUNCTION session_signed_in() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.signed_in_at := now();
    RETURN NEW;
END
$$;
ALTER FUNCTION session_signed_in() OWNER TO fs_owner;

DROP TRIGGER IF EXISTS session_signed_in ON session;
CREATE TRIGGER session_signed_in BEFORE UPDATE OF key ON session FOR EACH ROW EXECUTE FUNCTION session_signed_in();

CREATE INDEX IF NOT EXISTS session_signed_in_at ON session (signed_in_at);

REVOKE ALL ON session FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON session TO fs_forgejo;
GRANT SELECT, DELETE ON session TO fs_lifecycle;
