1. Activity story

The activity runs as `dev.dana` from `office-ws-1`, directed at `db-1`.
It began at 2026-07-26T11:04:03+00:00 and finished at 2026-07-26T11:04:46+00:00.

2. What was executed

Step 1 — on `office-ws-1` as `dev.dana`, from 2026-07-26T11:04:03+00:00 to 2026-07-26T11:04:11+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@db-1 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@db-1: Permission denied (publickey,password).

Step 2 — on `office-ws-1` as `dev.dana`, from 2026-07-26T11:04:17+00:00 to 2026-07-26T11:04:22+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@db-1 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@db-1: Permission denied (publickey,password).

Step 3 — on `office-ws-1` as `dev.dana`, from 2026-07-26T11:04:28+00:00 to 2026-07-26T11:04:33+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@db-1 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@db-1: Permission denied (publickey,password).

Step 4 — on `office-ws-1` as `dev.dana`, from 2026-07-26T11:04:39+00:00 to 2026-07-26T11:04:46+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@db-1 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@db-1: Permission denied (publickey,password).
