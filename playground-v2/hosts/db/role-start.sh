#!/bin/bash
# DB-role hook — boots the default postgres cluster + seeds the "app" database
# that web-tier baseline generators (batch 8) query against.
#
# What gets created (idempotent on rerun):
#   - role `appuser` with password `changeme` — used by web-1 / web-2 scheduler
#     actions via PGPASSWORD. Playground-only; production would use TLS + scram.
#   - database `app` owned by `appuser`.
#   - table `orders` with a handful of seed rows so SELECT-count queries
#     return non-zero. Schema is intentionally tiny — batch 8 just needs
#     measurable DB traffic, not a realistic OLTP workload.
#
# Also opens the cluster to in-network connections (listen_addresses='*',
# md5 auth) — the daemon default only binds to loopback, so without this
# web-1 → db-1 psql calls fail before authenticating. db-1 is on the compose
# bridge only (no host port), so network exposure is the docker DNS surface.
set -euo pipefail

service postgresql start >/dev/null

# Resolve the cluster's config dir so this survives a minor-version bump
# (PG 14/15/16 each live at a different /etc/postgresql path).
PG_CONF_DIR=$(find /etc/postgresql -maxdepth 2 -name postgresql.conf -printf '%h\n' | head -n1)
if [[ -z "${PG_CONF_DIR}" ]]; then
  echo "[db/role-start] FATAL: no postgresql.conf under /etc/postgresql" >&2
  exit 1
fi

# Open listen_addresses once — the sed is idempotent via a sentinel comment.
if ! grep -q "# soc-playground: listen_addresses" "${PG_CONF_DIR}/postgresql.conf"; then
  printf "\n# soc-playground: listen_addresses\nlisten_addresses = '*'\n" \
    >> "${PG_CONF_DIR}/postgresql.conf"
fi

# pg_hba: md5 auth for the docker network. Append-once via sentinel.
if ! grep -q "# soc-playground: docker-network md5" "${PG_CONF_DIR}/pg_hba.conf"; then
  cat >> "${PG_CONF_DIR}/pg_hba.conf" <<'EOF'

# soc-playground: docker-network md5
host    all             all             0.0.0.0/0               md5
EOF
fi

service postgresql reload >/dev/null

# Seed role + DB + table as the postgres superuser. Each step is check-before-
# create so rerunning is safe.
sudo -u postgres psql -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'appuser') THEN
    CREATE ROLE appuser LOGIN PASSWORD 'changeme';
  END IF;
END
$$;
SQL

if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='app'" | grep -q 1; then
  sudo -u postgres createdb -O appuser app
fi

sudo -u postgres psql -d app -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS orders (
  id         SERIAL PRIMARY KEY,
  customer   TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  placed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO orders (customer, amount_cents)
SELECT 'seed-customer-' || g, (g * 1000)
FROM generate_series(1, 25) AS g
WHERE NOT EXISTS (SELECT 1 FROM orders);
GRANT SELECT, INSERT ON orders TO appuser;
GRANT USAGE, SELECT ON SEQUENCE orders_id_seq TO appuser;
SQL
