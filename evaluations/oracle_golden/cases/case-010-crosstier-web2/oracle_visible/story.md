1. Activity story

The activity runs as `dev.dana` from `office-ws-1`, directed at `web-2`.
It began at 2026-07-26T20:06:02+00:00 and finished at 2026-07-26T20:06:42+00:00.

2. What was executed

Step 1 — on `office-ws-1` as `dev.dana`, from 2026-07-26T20:06:02+00:00 to 2026-07-26T20:06:09+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@web-2 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    Warning: Permanently added 'web-2' (ED25519) to the list of known hosts.
    dev.dana@web-2: Permission denied (publickey,password).

Step 2 — on `office-ws-1` as `dev.dana`, from 2026-07-26T20:06:15+00:00 to 2026-07-26T20:06:20+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@web-2 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@web-2: Permission denied (publickey,password).

Step 3 — on `office-ws-1` as `dev.dana`, from 2026-07-26T20:06:26+00:00 to 2026-07-26T20:06:31+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@web-2 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@web-2: Permission denied (publickey,password).

Step 4 — on `office-ws-1` as `dev.dana`, from 2026-07-26T20:06:37+00:00 to 2026-07-26T20:06:42+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@web-2 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@web-2: Permission denied (publickey,password).
