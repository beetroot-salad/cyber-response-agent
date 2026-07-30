1. Activity story

The activity runs as `dev.dana` from `office-ws-1`, directed at `office-ws-1`.
It began at 2026-07-28T06:46:42+00:00 and finished at 2026-07-28T06:47:19+00:00.

2. What was executed

Step 1 — on `office-ws-1` as `dev.dana`, from 2026-07-28T06:46:42+00:00 to 2026-07-28T06:46:45+00:00 (exit status 0):

    for user in admin sre.alice dev.dana svc.backups operator; do
      curl -sS -m 5 -o /dev/null -w "%{http_code} dev.dana\n" \
        -d "client_id=admin-cli" -d "grant_type=password" \
        -d "username=dev.dana" -d "password=Password123!" \
        "http://keycloak:8080/realms/soc-playground/protocol/openid-connect/token" \
        2>&1 || true
    done

It printed:

    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana

Step 2 — on `office-ws-1` as `dev.dana`, from 2026-07-28T06:46:49+00:00 to 2026-07-28T06:46:52+00:00 (exit status 0):

    for user in admin sre.alice dev.dana svc.backups operator; do
      curl -sS -m 5 -o /dev/null -w "%{http_code} dev.dana\n" \
        -d "client_id=admin-cli" -d "grant_type=password" \
        -d "username=dev.dana" -d "password=Password123!" \
        "http://keycloak:8080/realms/soc-playground/protocol/openid-connect/token" \
        2>&1 || true
    done

It printed:

    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana

Step 3 — on `office-ws-1` as `dev.dana`, from 2026-07-28T06:46:56+00:00 to 2026-07-28T06:46:58+00:00 (exit status 0):

    for user in admin sre.alice dev.dana svc.backups operator; do
      curl -sS -m 5 -o /dev/null -w "%{http_code} dev.dana\n" \
        -d "client_id=admin-cli" -d "grant_type=password" \
        -d "username=dev.dana" -d "password=Password123!" \
        "http://keycloak:8080/realms/soc-playground/protocol/openid-connect/token" \
        2>&1 || true
    done

It printed:

    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana

Step 4 — on `office-ws-1` as `dev.dana`, from 2026-07-28T06:47:02+00:00 to 2026-07-28T06:47:05+00:00 (exit status 0):

    for user in admin sre.alice dev.dana svc.backups operator; do
      curl -sS -m 5 -o /dev/null -w "%{http_code} dev.dana\n" \
        -d "client_id=admin-cli" -d "grant_type=password" \
        -d "username=dev.dana" -d "password=Password123!" \
        "http://keycloak:8080/realms/soc-playground/protocol/openid-connect/token" \
        2>&1 || true
    done

It printed:

    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana

Step 5 — on `office-ws-1` as `dev.dana`, from 2026-07-28T06:47:09+00:00 to 2026-07-28T06:47:12+00:00 (exit status 0):

    for user in admin sre.alice dev.dana svc.backups operator; do
      curl -sS -m 5 -o /dev/null -w "%{http_code} dev.dana\n" \
        -d "client_id=admin-cli" -d "grant_type=password" \
        -d "username=dev.dana" -d "password=Password123!" \
        "http://keycloak:8080/realms/soc-playground/protocol/openid-connect/token" \
        2>&1 || true
    done

It printed:

    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana

Step 6 — on `office-ws-1` as `dev.dana`, from 2026-07-28T06:47:16+00:00 to 2026-07-28T06:47:19+00:00 (exit status 0):

    for user in admin sre.alice dev.dana svc.backups operator; do
      curl -sS -m 5 -o /dev/null -w "%{http_code} dev.dana\n" \
        -d "client_id=admin-cli" -d "grant_type=password" \
        -d "username=dev.dana" -d "password=Password123!" \
        "http://keycloak:8080/realms/soc-playground/protocol/openid-connect/token" \
        2>&1 || true
    done

It printed:

    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana
    401 dev.dana
