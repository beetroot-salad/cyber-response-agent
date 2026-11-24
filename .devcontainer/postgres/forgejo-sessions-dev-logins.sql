-- The dev stack's two logins on Forgejo's sessions database (#1592), password `dev-only-change-me`: `fs_forgejo_dev` in
-- `fs_forgejo` (forgejo/settings.env's `PROVIDER_CONFIG`) and `fs_lifecycle_dev` in `fs_lifecycle` (the lifecycle's
-- `DEFENDER_LIFECYCLE_FORGE_SESSIONS_DSN`). Run after forgejo-sessions.sql by compose's `forgejo-sessions` service; it
-- may be run again. A deployment makes its own logins instead.
\set ON_ERROR_STOP on
DO $$ BEGIN CREATE ROLE fs_forgejo_dev LOGIN PASSWORD 'dev-only-change-me' IN ROLE fs_forgejo;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE fs_lifecycle_dev LOGIN PASSWORD 'dev-only-change-me' IN ROLE fs_lifecycle;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
