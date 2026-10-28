-- Runs once, when the dev data volume is first initialised (#1339): the application's database,
-- beside the `keycloak` one that POSTGRES_DB creates. Apply the schema with
-- `DEFENDER_DATABASE_DSN=postgresql://defender:dev-only-change-me@postgres:5432/defender python -m defender.migrations upgrade`.
CREATE DATABASE defender;
