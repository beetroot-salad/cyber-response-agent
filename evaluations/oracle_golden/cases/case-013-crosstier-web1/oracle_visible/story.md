1. Activity story

The activity runs as `dev.dana` from `office-ws-1`, directed at `web-1`.
It began at 2026-07-27T10:39:52+00:00 and finished at 2026-07-27T10:40:30+00:00.

2. What was executed

Step 1 — on `office-ws-1` as `dev.dana`, from 2026-07-27T10:39:52+00:00 to 2026-07-27T10:39:57+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@web-1 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@web-1: Permission denied (publickey,password).

Step 2 — on `office-ws-1` as `dev.dana`, from 2026-07-27T10:40:03+00:00 to 2026-07-27T10:40:08+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@web-1 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@web-1: Permission denied (publickey,password).

Step 3 — on `office-ws-1` as `dev.dana`, from 2026-07-27T10:40:14+00:00 to 2026-07-27T10:40:19+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@web-1 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@web-1: Permission denied (publickey,password).

Step 4 — on `office-ws-1` as `dev.dana`, from 2026-07-27T10:40:25+00:00 to 2026-07-27T10:40:30+00:00 (exit status 0):

    sshpass -p changeme ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 \
      dev.dana@web-1 "id; hostname; ls /var/lib/postgresql 2>&1 | head -3" \
      2>&1 | head -5 || true

It printed:

    dev.dana@web-1: Permission denied (publickey,password).
