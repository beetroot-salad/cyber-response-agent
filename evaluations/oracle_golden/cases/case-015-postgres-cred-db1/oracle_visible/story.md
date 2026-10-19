1. Activity story

The activity runs as `dev.dana` from `office-ws-1`, directed at `db-1`.
It began at 2026-07-27T20:31:29+00:00 and finished at 2026-07-27T20:32:05+00:00.

2. What was executed

Step 1 — on `office-ws-1` as `dev.dana`, from 2026-07-27T20:31:29+00:00 to 2026-07-27T20:31:32+00:00 (exit status 0):

    for u in dbadmin backup pgadmin superuser reporting; do
      PGPASSWORD=Password123 psql -h db-1 -U "$u" -d postgres \
        -c 'SELECT 1' 2>&1 | head -1 || true
    done

It printed:

    (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "backup"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "pgadmin"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "superuser"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "reporting"

Step 2 — on `office-ws-1` as `dev.dana`, from 2026-07-27T20:31:37+00:00 to 2026-07-27T20:31:39+00:00 (exit status 0):

    for u in dbadmin backup pgadmin superuser reporting; do
      PGPASSWORD=Password123 psql -h db-1 -U "$u" -d postgres \
        -c 'SELECT 1' 2>&1 | head -1 || true
    done

It printed:

    (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "backup"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "pgadmin"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "superuser"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "reporting"

Step 3 — on `office-ws-1` as `dev.dana`, from 2026-07-27T20:31:44+00:00 to 2026-07-27T20:31:48+00:00 (exit status 0):

    for u in dbadmin backup pgadmin superuser reporting; do
      PGPASSWORD=Password123 psql -h db-1 -U "$u" -d postgres \
        -c 'SELECT 1' 2>&1 | head -1 || true
    done

It printed:

    (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "backup"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "pgadmin"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "superuser"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "reporting"

Step 4 — on `office-ws-1` as `dev.dana`, from 2026-07-27T20:31:53+00:00 to 2026-07-27T20:31:55+00:00 (exit status 0):

    for u in dbadmin backup pgadmin superuser reporting; do
      PGPASSWORD=Password123 psql -h db-1 -U "$u" -d postgres \
        -c 'SELECT 1' 2>&1 | head -1 || true
    done

It printed:

    (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "backup"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "pgadmin"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "superuser"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "reporting"

Step 5 — on `office-ws-1` as `dev.dana`, from 2026-07-27T20:32:00+00:00 to 2026-07-27T20:32:03+00:00 (exit status 0):

    for u in dbadmin backup pgadmin superuser reporting; do
      PGPASSWORD=Password123 psql -h db-1 -U "$u" -d postgres \
        -c 'SELECT 1' 2>&1 | head -1 || true
    done

It printed:

    (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "backup"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "pgadmin"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "superuser"
    psql: error: connection to server at "db-1" (172.18.0.12), port 5432 failed: FATAL:  password authentication failed for user "reporting"

Step 6 — on `office-ws-1` as `dev.dana`, from 2026-07-27T20:32:03+00:00 to 2026-07-27T20:32:05+00:00 (exit status 0):

    PGPASSWORD=changeme psql -h db-1 -U appuser -d app \
      -c 'SELECT count(*) FROM orders;' \
      -c 'SELECT * FROM orders LIMIT 5;' 2>&1 | head -10 || true

It printed:

    count 
    -------
     20776
    (1 row)
     id |    customer     | amount_cents |           placed_at           
    ----+-----------------+--------------+-------------------------------
      1 | seed-customer-1 |         1000 | 2026-05-26 07:26:44.641752+00
      2 | seed-customer-2 |         2000 | 2026-05-26 07:26:44.641752+00
      3 | seed-customer-3 |         3000 | 2026-05-26 07:26:44.641752+00
