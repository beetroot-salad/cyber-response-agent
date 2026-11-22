-- Forgejo's sessions database (#1592 PP-5, OD-4): its roles, the database and who may connect, then its one table
-- (`forgejo-sessions-table.sql`). Not a defender migration: the table is Forgejo's. Run with psql as a superuser, in
-- any database, by `.devcontainer/forgejo/setup.sh` (`psql -f /defender-postgres/forgejo-sessions.sql`); it may be
-- run again on an existing server.
--
-- Nobody logs in as these roles. The operator makes one login in `fs_forgejo` (Forgejo's `[session] PROVIDER_CONFIG`)
-- and one in `fs_lifecycle` (the lifecycle's `DEFENDER_LIFECYCLE_FORGE_SESSIONS_DSN`); no other login can connect.
\set ON_ERROR_STOP on

-- Roles are cluster-wide: another session may create one at this same moment, so the create itself decides (as
-- migration 0015 does).
DO $$ BEGIN CREATE ROLE fs_owner NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE fs_forgejo NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE fs_lifecycle NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;

SELECT 'CREATE DATABASE forgejo_sessions OWNER fs_owner'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'forgejo_sessions')\gexec

REVOKE ALL ON DATABASE forgejo_sessions FROM PUBLIC;
GRANT CONNECT ON DATABASE forgejo_sessions TO fs_forgejo, fs_lifecycle;

\connect forgejo_sessions
\ir forgejo-sessions-table.sql
