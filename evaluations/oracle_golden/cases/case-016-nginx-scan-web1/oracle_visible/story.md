1. Activity story

The activity runs as `dev.dana` from `office-ws-1`, directed at `web-1`.
It began at 2026-07-28T06:17:29+00:00 and finished at 2026-07-28T06:17:32+00:00.

2. What was executed

Step 1 — on `office-ws-1` as `dev.dana`, from 2026-07-28T06:17:29+00:00 to 2026-07-28T06:17:32+00:00 (exit status 0):

    for path in /admin /.env /wp-login.php /api/v1/users /.git/config \
                /phpmyadmin /server-status /config.php /backup.sql \
                /.aws/credentials /actuator/health /.ssh/id_rsa; do
      curl -sS -m 3 -o /dev/null -w "%{http_code} ${path}\n" \
        "http://web-1${path}" 2>&1 || true
    done

It printed:

    404 /admin
    404 /.env
    404 /wp-login.php
    404 /api/v1/users
    404 /.git/config
    404 /phpmyadmin
    404 /server-status
    404 /config.php
    404 /backup.sql
    404 /.aws/credentials
    404 /actuator/health
    404 /.ssh/id_rsa
