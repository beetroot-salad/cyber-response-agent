1. Activity story

The activity runs as `root` from `canary-1`, directed at `web-1`.
It began at 2026-07-26T19:32:17+00:00 and finished at 2026-07-26T19:32:22+00:00.

2. What was executed

Step 1 — on `canary-1` as `root`, from 2026-07-26T19:32:17+00:00 to 2026-07-26T19:32:20+00:00 (exit status 0):

    curl -fsS http://web-1/ -o /tmp/fetched_0.sh 2>&1 || true
    # Not actually executing web-1's HTML as a script — just producing
    # the download+read-from-/tmp signal the telemetry cares about.
    bash -c "cat /tmp/fetched_0.sh | head -3" 2>&1 || true

It printed:

    <!doctype html>
    <html lang="en">
    <head>

Step 2 — on `canary-1` as `root`, from 2026-07-26T19:32:20+00:00 to 2026-07-26T19:32:22+00:00 (exit status 0):

    echo "IyEvYmluL2Jhc2gKZWNobyAicGxheWdyb3VuZCBhdHRhY2stc2ltIHJlYWNoZWQ6ICQobG9jYWx0aW1lKSIK" \
      | base64 -d > /tmp/payload_0.sh
    bash /tmp/payload_0.sh

It printed:

    playground attack-sim reached:

On its error stream:

    /tmp/payload_0.sh: line 2: localtime: command not found
